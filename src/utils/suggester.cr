module Authz0
  # "Did you mean …?" suggestions for mistyped commands. Plain Levenshtein
  # with a small distance cutoff so only near-misses are offered.
  module Suggester
    extend self

    def suggest(input : String, candidates : Array(String), max_distance : Int32 = 3) : String?
      best : String? = nil
      best_distance = max_distance + 1
      candidates.each do |candidate|
        d = distance(input, candidate)
        if d < best_distance
          best_distance = d
          best = candidate
        end
      end
      best_distance <= max_distance ? best : nil
    end

    def distance(a : String, b : String) : Int32
      ac = a.chars
      bc = b.chars
      m = ac.size
      n = bc.size
      return n if m == 0
      return m if n == 0

      prev = (0..n).to_a
      curr = Array(Int32).new(n + 1, 0)
      ac.each_with_index do |ca, i|
        curr[0] = i + 1
        bc.each_with_index do |cb, j|
          cost = ca == cb ? 0 : 1
          curr[j + 1] = Math.min(Math.min(curr[j] + 1, prev[j + 1] + 1), prev[j] + cost)
        end
        prev, curr = curr, prev
      end
      prev[n]
    end
  end
end
