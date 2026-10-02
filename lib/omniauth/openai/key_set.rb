# frozen_string_literal: true

module OmniAuth
  module OpenAI
    # The issuer's signing keys, shared by every request in the process.
    #
    # Keys are kept for +ttl+ seconds. When a token names a key the set lacks,
    # ruby-jwt asks again with +kid_not_found+, and the set downloads afresh so
    # a rotated key is picked up at once. Those forced downloads happen at most
    # once per +refresh_interval+, so a stream of bad tokens cannot turn into a
    # stream of requests to the issuer.
    class KeySet
      def initialize(ttl: 3600, refresh_interval: 300, clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) })
        @ttl = ttl
        @refresh_interval = refresh_interval
        @clock = clock
        @lock = Mutex.new
        @keys = nil
        @fetched_at = nil
      end

      # Returns the JWKS hash, calling the block to download it when needed.
      def fetch(kid_not_found: false)
        @lock.synchronize do
          if stale? || (kid_not_found && refreshable?)
            @keys = yield
            @fetched_at = now
          end
          @keys
        end
      end

      private

      def stale?
        @keys.nil? || now - @fetched_at >= @ttl
      end

      def refreshable?
        now - @fetched_at >= @refresh_interval
      end

      def now
        @clock.call
      end
    end
  end
end
