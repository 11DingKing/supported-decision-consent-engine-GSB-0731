# frozen_string_literal: true

module ConsentEngine
  # Pure-domain authorizer. Takes a frozen set of events (already bounded by
  # seen_seq) plus a decision time, and returns an AuthorizationDecision.
  #
  # It performs ZERO I/O and never depends on the current wall clock, so the
  # same (events, decision_time) tuple MUST produce an identical result on
  # replay. This class is the only place where authorization rules live.
  class Authorizer
    # Higher number = more specific / stronger denial reason.
    DENIAL_PRIORITY = {
      ReasonCodes::PERSON_OR_SUPPORTER_UNKNOWN => 100,
      ReasonCodes::REVOKED_BEFORE_GRANT        => 90,
      ReasonCodes::REVOKED                     => 80,
      ReasonCodes::DELEGATION_AFTER_REVOCATION => 75,
      ReasonCodes::DELEGATION_CYCLE            => 70,
      ReasonCodes::DELEGATION_BUDGET_EXCEEDED  => 65,
      ReasonCodes::DELEGATION_BROAD            => 60,
      ReasonCodes::DELEGATION_SOURCE_SCOPE_MISSING => 59,
      ReasonCodes::WITNESS_MISSING             => 50,
      ReasonCodes::DELEGATION_SOURCE_REVOKED   => 40,
      ReasonCodes::DELEGATION_EXPIRED          => 35,
      ReasonCodes::DELEGATION_SOURCE_EXPIRED   => 30,
      ReasonCodes::DELEGATION_BEFORE_SOURCE    => 25,
      ReasonCodes::DELEGATION_LATE             => 24,
      ReasonCodes::EXPIRED                     => 20,
      ReasonCodes::NOT_YET_VALID               => 15,
      ReasonCodes::EMERGENCY_TIMEOUT           => 12,
      ReasonCodes::EMERGENCY_WITHOUT_REVIEW_EVENT => 11,
      ReasonCodes::EMERGENCY_SCOPE_NOT_ALLOWED => 10,
      ReasonCodes::SCOPE_MISSING               => 5,
      ReasonCodes::DELEGATION_DENIED           => 2,
      ReasonCodes::SILENT_NO_CONSENT           => 0
    }.freeze

    # @param events Array[Event] pre-filtered to seq <= seen_seq, ordered by seq.
    # @param person_id     [String]
    # @param supporter_id  [String,nil] nil only for emergency path
    # @param scope         [String]
    # @param decision_at   [Time]
    # @param seen_seq      [Integer]
    # @param emergency_config [Hash,nil] :allowed_scope, :max_minutes, :requires_review_event
    def self.decide(events:, person_id:, supporter_id:, scope:, decision_at:, seen_seq:, emergency_config: nil)
      new(events, person_id, supporter_id, scope, decision_at, seen_seq, emergency_config).call
    end

    def initialize(events, person_id, supporter_id, scope, decision_at, seen_seq, emergency_config)
      @events           = events
      @person_id        = person_id
      @supporter_id     = supporter_id
      @scope            = scope
      @decision_at      = decision_at
      @seen_seq         = seen_seq
      @emergency_config = emergency_config || {}
    end

    def call
      # 1. Structural: unknown person / supporter -> default deny.
      if !person_registered?
        return deny(ReasonCodes::PERSON_OR_SUPPORTER_UNKNOWN)
      end
      if @supporter_id && !supporter_registered?(@supporter_id)
        return deny(ReasonCodes::PERSON_OR_SUPPORTER_UNKNOWN)
      end

      # 2. Ordinary consent (direct from the person to the supporter).
      #    Evaluated first because an explicit grant always wins.
      direct = evaluate_direct
      return direct if direct.granted?

      # 3. Delegation chain.
      delegated = evaluate_delegation
      return delegated if delegated.granted?

      # 4. Emergency path: only grants for the configured allowed scope, and
      #    only if no ordinary consent or delegation already granted. It is
      #    evaluated after ordinary paths so that a valid direct consent for
      #    a different scope is not masked by EMERGENCY_SCOPE_NOT_ALLOWED.
      emergency = evaluate_emergency
      return emergency if emergency&.granted?

      # 5. Pick the most specific denial among all paths.
      candidates = [direct, delegated, emergency].compact
      candidates.reduce { |best, d| stronger_denial?(d, best) ? d : best } ||
        deny(ReasonCodes::SILENT_NO_CONSENT)
    end

    private

    # ---------- emergency ----------

    def evaluate_emergency
      return nil unless @emergency_config[:allowed_scope]
      return nil unless @supporter_id.nil? || @supporter_id == @emergency_config[:supporter_id] || true

      activations = @events.select do |e|
        e.type == "EMERGENCY_ACTIVATED" &&
          e.payload["personId"] == @person_id
      end

      return nil if activations.empty?

      review_event_present = @events.any? do |e|
        e.type == "EMERGENCY_REVIEWED" && e.payload["personId"] == @person_id
      end

      max_minutes = @emergency_config[:max_minutes].to_i

      best = nil
      activations.each do |act|
        next if act.effective_at > @decision_at

        window_end = act.effective_at + (max_minutes * 60)
        in_window = @decision_at < window_end

        if @scope != @emergency_config[:allowed_scope]
          c = deny(ReasonCodes::EMERGENCY_SCOPE_NOT_ALLOWED, [emergency_link(act)])
        elsif !in_window
          c = deny(ReasonCodes::EMERGENCY_TIMEOUT, [emergency_link(act)])
        elsif @emergency_config[:requires_review_event] && !review_event_present
          c = deny(ReasonCodes::EMERGENCY_WITHOUT_REVIEW_EVENT, [emergency_link(act)])
        else
          c = AuthorizationDecision.new(
            granted: true,
            reason_code: ReasonCodes::GRANTED_EMERGENCY,
            scope: @scope,
            chain: [emergency_link(act)],
            decision_at: @decision_at,
            seen_seq: @seen_seq,
            subject_id: act.payload["supporterId"]
          )
          return c
        end
        best = c if best.nil? || stronger_denial?(c, best)
      end
      best
    end

    def emergency_link(act)
      ChainLink.new(
        kind: "EMERGENCY",
        event_id: act.event_id,
        from_id: @person_id,
        to_id: act.payload["supporterId"],
        scopes: [@emergency_config[:allowed_scope]],
        effective_at: act.effective_at,
        expires_at: act.effective_at + (@emergency_config[:max_minutes].to_i * 60)
      )
    end

    # ---------- direct consent ----------

    def evaluate_direct
      matching = @events.select do |e|
        e.type == "CONSENT_GRANTED" &&
          e.payload["personId"] == @person_id &&
          e.payload["supporterId"] == @supporter_id
      end

      return deny(ReasonCodes::SILENT_NO_CONSENT) if matching.empty?

      best = nil
      matching.each do |consent_ev|
        result = evaluate_consent_event(consent_ev)
        if result.granted?
          return AuthorizationDecision.new(
            granted: true,
            reason_code: ReasonCodes::GRANTED,
            scope: @scope,
            chain: [consent_link(consent_ev)],
            decision_at: @decision_at,
            seen_seq: @seen_seq,
            subject_id: @supporter_id
          )
        end
        best = result if best.nil? || stronger_denial?(result, best)
      end
      best
    end

    def evaluate_consent_event(consent_ev)
      scopes    = Array(consent_ev.payload["scopes"])
      from_time = consent_ev.effective_at
      to_time   = consent_ev.payload["to"] ? Time.iso8601(consent_ev.payload["to"]) : nil
      witness   = consent_ev.payload["witnessId"]

      # Revocation: the EARLIEST effective revocation at or before the decision
      # time governs. Out-of-order arrivals (a later-seq revoke with an earlier
      # effective_at) are handled correctly because we compare business times.
      revoke = earliest_revocation_for(consent_ev.event_id)
      if revoke
        if revoke.effective_at <= consent_ev.effective_at
          return deny(ReasonCodes::REVOKED_BEFORE_GRANT, [consent_link(consent_ev)])
        end
        if revoke.effective_at <= @decision_at
          return deny(ReasonCodes::REVOKED, [consent_link(consent_ev)])
        end
      end

      if witness.nil? || witness.to_s.empty?
        return deny(ReasonCodes::WITNESS_MISSING, [consent_link(consent_ev)])
      end
      if to_time && @decision_at >= to_time
        return deny(ReasonCodes::EXPIRED, [consent_link(consent_ev)])
      end
      if @decision_at < from_time
        return deny(ReasonCodes::NOT_YET_VALID, [consent_link(consent_ev)])
      end
      unless scopes.include?(@scope)
        return deny(ReasonCodes::SCOPE_MISSING, [consent_link(consent_ev)])
      end

      AuthorizationDecision.new(
        granted: true,
        reason_code: ReasonCodes::GRANTED,
        scope: @scope,
        chain: [consent_link(consent_ev)],
        decision_at: @decision_at,
        seen_seq: @seen_seq,
        subject_id: @supporter_id
      )
    end

    def consent_link(consent_ev)
      ChainLink.new(
        kind: "PERSON_CONSENT",
        event_id: consent_ev.event_id,
        from_id: @person_id,
        to_id: consent_ev.payload["supporterId"],
        scopes: consent_ev.payload["scopes"],
        effective_at: consent_ev.effective_at,
        expires_at: consent_ev.payload["to"] ? Time.iso8601(consent_ev.payload["to"]) : nil,
        witness_id: consent_ev.payload["witnessId"]
      )
    end

    # ---------- delegation ----------

    def evaluate_delegation
      all_delegations = @events.select { |e| e.type == "DELEGATION_GRANTED" }

      root_consents = @events.select do |e|
        e.type == "CONSENT_GRANTED" && e.payload["personId"] == @person_id
      end

      best_denial = nil

      root_consents.each do |root|
        next unless @supporter_id != root.payload["supporterId"]

        # At the first hop, only delegations that explicitly cite this root
        # consent as their sourceConsentId may leave it. This prevents a
        # delegation under consent C2 from being treated as authority under
        # a different consent C1 held by the same supporter.
        root_delegations = all_delegations.select do |d|
          d.payload["sourceConsentId"] == root.event_id
        end

        result = walk_chain(
          current_event: root,
          delegations: root_delegations,
          all_delegations: all_delegations,
          visited_deleg_ids: [],
          chain_acc: [consent_link(root)]
        )
        next if result.nil?
        return result if result.granted?
        best_denial = result if best_denial.nil? || stronger_denial?(result, best_denial)
      end

      best_denial || deny(ReasonCodes::SILENT_NO_CONSENT)
    end

    # DFS that only returns a non-nil result along paths that actually reach
    # @supporter_id. This is critical: without target-awareness, an invalid
    # delegation between two unrelated supporters would surface as a denial
    # for a third party, incorrectly replacing SILENT_NO_CONSENT.
    #
    # +delegations+ is the set of outgoing delegations from the current hop
    # (filtered by sourceConsentId for the first hop). +all_delegations+ is
    # the full set, used to find onward hops after a delegation (where the
    # "source" for the next hop is the delegation itself, identified by
    # matching fromSupporterId — a sub-delegation does not repeat the
    # original consent id in sourceConsentId).
    def walk_chain(current_event:, delegations:, all_delegations:, visited_deleg_ids:, chain_acc:)
      current_holder =
        if current_event.type == "CONSENT_GRANTED"
          current_event.payload["supporterId"]
        else
          current_event.payload["toSupporterId"]
        end

      outgoing = delegations.select do |d|
        d.payload["fromSupporterId"] == current_holder &&
          !visited_deleg_ids.include?(d.event_id)
      end

      # No path from here leads to @supporter_id.
      return nil if outgoing.empty?

      best = nil
      outgoing.each do |d|
        d_scopes = Array(d.payload["scopes"])
        # A hop that does not even mention the requested scope cannot be part
        # of a grant path for this query, and must not shadow more specific
        # denials (such as a source revocation on a different delegation).
        next unless d_scopes.include?(@scope)

        new_chain = chain_acc + [delegation_link(d)]

        # If this hop itself points to our supporter, evaluate it directly.
        if d.payload["toSupporterId"] == @supporter_id
          validation = validate_delegation_hop(d, current_event, new_chain)
          if validation
            best = validation if best.nil? || stronger_denial?(validation, best)
            next
          end
          return AuthorizationDecision.new(
            granted: true,
            reason_code: ReasonCodes::GRANTED_VIA_DELEGATION,
            scope: @scope,
            chain: new_chain,
            decision_at: @decision_at,
            seen_seq: @seen_seq,
            subject_id: @supporter_id
          )
        end

        # Otherwise, only descend if there is a path onward to @supporter_id.
        next unless chain_reaches_target?(d, all_delegations, visited_deleg_ids + [d.event_id])

        validation = validate_delegation_hop(d, current_event, new_chain)
        if validation
          best = validation if best.nil? || stronger_denial?(validation, best)
          next
        end

        sub = walk_chain(
          current_event: d,
          delegations: all_delegations,
          all_delegations: all_delegations,
          visited_deleg_ids: visited_deleg_ids + [d.event_id],
          chain_acc: new_chain
        )
        next if sub.nil?
        return sub if sub.granted?
        best = sub if best.nil? || stronger_denial?(sub, best)
      end
      best
    end

    # Returns true iff a chain of delegations can reach @supporter_id from
    # +from_event+ without revisiting a delegation id (cycle protection).
    def chain_reaches_target?(from_event, delegations, visited)
      holder = from_event.payload["toSupporterId"]
      return true if holder == @supporter_id

      delegations.any? do |d|
        next false if visited.include?(d.event_id)
        next false unless d.payload["fromSupporterId"] == holder
        next false unless Array(d.payload["scopes"]).include?(@scope)
        d.payload["toSupporterId"] == @supporter_id ||
          chain_reaches_target?(d, delegations, visited + [d.event_id])
      end
    end

    def validate_delegation_hop(d, source_event, chain)
      d_scopes  = Array(d.payload["scopes"])
      src_scopes = Array(source_event.payload["scopes"])

      # Scope narrowing: delegation may only carry a subset of source scopes.
      unless d_scopes.all? { |s| src_scopes.include?(s) }
        return deny(ReasonCodes::DELEGATION_BROAD, chain)
      end
      unless d_scopes.include?(@scope)
        return deny(ReasonCodes::DELEGATION_SOURCE_SCOPE_MISSING, chain)
      end

      # Delegation cannot pre-date the source grant (no retroactive authority).
      if d.effective_at < source_event.effective_at
        return deny(ReasonCodes::DELEGATION_BEFORE_SOURCE, chain)
      end

      # --- Seq-order revocation check (Round 2) ---
      # A delegation appended AFTER a revocation event (in audit sequence)
      # cannot claim authority even if its business effective_at is earlier.
      # This blocks the race: revoke arrives first, then a late delegation
      # tries to sneak in with a back-dated effective_at.
      if source_event.type == "CONSENT_GRANTED"
        revoke = revocation_event_for(source_event.event_id)
        if revoke && d.seq > revoke.seq
          return deny(ReasonCodes::DELEGATION_AFTER_REVOCATION, chain)
        end
        if revoke && revoke.effective_at <= @decision_at && revoke.seq < d.seq
          return deny(ReasonCodes::DELEGATION_AFTER_REVOCATION, chain)
        end
      end

      # Delegation own expiry.
      d_to = d.payload["to"] ? Time.iso8601(d.payload["to"]) : nil
      if d_to && @decision_at >= d_to
        return deny(ReasonCodes::DELEGATION_EXPIRED, chain)
      end
      if d.effective_at > @decision_at
        return deny(ReasonCodes::NOT_YET_VALID, chain)
      end

      # Source consent validity at decision time.
      if source_event.type == "CONSENT_GRANTED"
        src_revoke = earliest_revocation_for(source_event.event_id)
        if src_revoke && src_revoke.effective_at <= @decision_at
          return deny(ReasonCodes::DELEGATION_SOURCE_REVOKED, chain)
        end
        src_to = source_event.payload["to"] ? Time.iso8601(source_event.payload["to"]) : nil
        if src_to && @decision_at >= src_to
          return deny(ReasonCodes::DELEGATION_SOURCE_EXPIRED, chain)
        end
      end

      # --- Cumulative budget across sibling sub-delegations (Round 2) ---
      if source_event.type == "CONSENT_GRANTED"
        budget_error = check_cumulative_budget(source_event, d)
        return budget_error if budget_error
      end

      nil
    end

    # Find the revocation event (regardless of whether it is effective at
    # decision time) — used for seq-order comparisons.
    def revocation_event_for(consent_event_id)
      @events.find do |e|
        e.type == "CONSENT_REVOKED" &&
          e.payload["consentId"] == consent_event_id
      end
    end

    # Validates that all sibling delegations under +source_event+ do not
    # collectively exceed the source's budget. The delegation +candidate+ is
    # included in the tally only if it would be active at decision time;
    # expired or not-yet-valid siblings are counted too (the budget was still
    # consumed when they were created), which is the conservative choice.
    def check_cumulative_budget(source_event, candidate)
      siblings = @events.select do |e|
        e.type == "DELEGATION_GRANTED" &&
          e.payload["sourceConsentId"] == source_event.event_id
      end

      # Emergency activations under this person also consume the source's
      # emergency budget. This consumed budget survives revocation — it is
      # counted regardless of whether the source is later revoked.
      activations = @events.select do |e|
        e.type == "EMERGENCY_ACTIVATED" &&
          e.payload["personId"] == @person_id
      end

      begin
        DelegationBudget.new(
          source_event, siblings, @decision_at, @seen_seq,
          emergency_activations: activations
        ).verify!
      rescue DelegationBudget::Exceeded => e
        return deny(ReasonCodes::DELEGATION_BUDGET_EXCEEDED,
                    chain_so_far_for(candidate))
      end
      nil
    end

    # When a budget violation is detected deep in walk_chain we don't always
    # have the full accumulated chain handy, so reconstruct one that includes
    # the source consent and the offending delegation.
    def chain_so_far_for(delegation_event)
      source = @events.find do |e|
        e.type == "CONSENT_GRANTED" &&
          e.event_id == delegation_event.payload["sourceConsentId"]
      end
      links = []
      links << consent_link(source) if source
      links << delegation_link(delegation_event)
      links
    end

    def delegation_link(d)
      ChainLink.new(
        kind: "DELEGATION",
        event_id: d.event_id,
        from_id: d.payload["fromSupporterId"],
        to_id: d.payload["toSupporterId"],
        scopes: d.payload["scopes"],
        effective_at: d.effective_at,
        expires_at: d.payload["to"] ? Time.iso8601(d.payload["to"]) : nil
      )
    end

    # ---------- helpers ----------

    # Earliest revocation (by business effective_at) that is active at or
    # before @decision_at. Using the earliest rather than the first-by-seq
    # means an out-of-order revocation (appended later but with an earlier
    # effective time) still governs correctly.
    def earliest_revocation_for(consent_event_id)
      @events
        .select do |e|
          e.type == "CONSENT_REVOKED" &&
            e.payload["consentId"] == consent_event_id &&
            e.effective_at <= @decision_at
        end
        .min_by(&:effective_at)
    end

    def person_registered?
      @events.any? do |e|
        e.type == "PERSON_REGISTERED" && e.payload["personId"] == @person_id
      end
    end

    def supporter_registered?(sid)
      @events.any? do |e|
        e.type == "SUPPORTER_REGISTERED" && e.payload["supporterId"] == sid
      end
    end

    def deny(code, chain = [])
      AuthorizationDecision.new(
        granted: false,
        reason_code: code,
        scope: @scope,
        chain: chain,
        decision_at: @decision_at,
        seen_seq: @seen_seq,
        subject_id: @supporter_id
      )
    end

    def stronger(a, b)
      return a if b.nil?
      return b if a.nil?
      stronger_denial?(a, b) ? a : b
    end

    def stronger_denial?(a, b)
      pa = DENIAL_PRIORITY.fetch(a.reason_code, -1)
      pb = DENIAL_PRIORITY.fetch(b.reason_code, -1)
      pa > pb
    end
  end
end
