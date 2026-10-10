module Proofgate
  # The object a policy file runs against. `allow`, `deny`, `never` and `always` read like
  # the rule they define, and each is checked as soon as it is written.
  class Builder
    attr_reader :name

    def initialize(name, file)
      @name = name.to_s
      @file = file
      @dimensions = []
      @rules = []
      @invariants = []
      @ids = {}
    end

    # policy_name "deploys"
    def policy_name(name)
      @name = name.to_s
    end

    # dimension :env, %w[dev staging prod]
    def dimension(name, values)
      name = name.to_s
      values = Array(values).map(&:to_s)
      fail_here("dimension '#{name}' is defined twice") if @dimensions.any? { |d| d[:name] == name }
      fail_here("dimension '#{name}' needs at least one value") if values.empty?
      @dimensions << { name: name, values: values }
    end

    # allow :sre_deploys, "SREs deploy with approval", role: "sre", approved: true
    def allow(id, description = nil, **conds)
      add_rule(:allow, id, description, conds)
    end

    def deny(id, description = nil, **conds)
      add_rule(:deny, id, description, conds)
    end

    # never :no_contractor_prod, "Contractors never touch prod", env: "prod", role: "contractor"
    def never(id, description = nil, **conds)
      add_invariant(:never_allow, id, description, conds)
    end

    # always :sre_can_roll_back, "SREs can always roll back", role: "sre", action: "rollback"
    def always(id, description = nil, **conds)
      add_invariant(:always_allow, id, description, conds)
    end

    def to_ir
      fail_here("policy has no dimensions") if @dimensions.empty?
      {
        "version" => 1,
        "name" => @name,
        "dimensions" => @dimensions.map { |d| { "name" => d[:name], "values" => d[:values] } },
        "rules" => @rules,
        "invariants" => @invariants
      }
    end

    private

    def add_rule(effect, id, description, conds)
      @rules << entry(id, description, conds).merge("effect" => effect.to_s)
    end

    def add_invariant(kind, id, description, conds)
      @invariants << entry(id, description, conds).merge("kind" => kind.to_s)
    end

    def entry(id, description, conds)
      id = id.to_s
      fail_here("'#{id}' is already used by another rule or invariant") if @ids[id]
      @ids[id] = true
      {
        "id" => id,
        "description" => description.to_s,
        "when" => normalize(id, conds)
      }
    end

    def normalize(id, conds)
      conds.each_with_object({}) do |(dim, vals), out|
        dim = dim.to_s
        known = @dimensions.find { |d| d[:name] == dim }
        fail_here("'#{id}' uses dimension '#{dim}', which is not defined above it") unless known
        vals = Array(vals).map(&:to_s)
        fail_here("'#{id}' has no values for '#{dim}'") if vals.empty?
        (vals - known[:values]).each do |v|
          fail_here("'#{id}' uses '#{v}' for '#{dim}'. Known values: #{known[:values].join(', ')}")
        end
        out[dim] = vals
      end
    end

    def fail_here(message)
      where = caller_locations.find { |l| @file && l.path == @file }
      raise Error, where ? "#{where.path}:#{where.lineno}: #{message}" : message
    end
  end
end
