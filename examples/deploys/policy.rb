# Who may do what to which environment. First matching rule wins, everything else is denied.
policy_name "deploys"

dimension :env,      %w[dev staging prod]
dimension :role,     %w[engineer sre contractor]
dimension :action,   %w[read deploy rollback delete]
dimension :approved, %w[yes no]

# Invariants are proven over every possible request, not sampled.
never  :no_contractor_prod,  "Contractors never change prod",
       env: "prod", role: "contractor", action: %w[deploy rollback delete]
never  :no_unapproved_prod,  "Nothing is deployed or deleted in prod without approval",
       env: "prod", action: %w[deploy delete], approved: "no"
always :sre_can_roll_back,   "SREs can always roll back",
       role: "sre", action: "rollback"

deny  :freeze_prod_delete,   "Nobody deletes in prod", env: "prod", action: "delete"
allow :sre_prod,             "SREs run prod with approval",
      env: "prod", role: "sre", approved: "yes"
allow :sre_rollback,         "SREs roll back anywhere", role: "sre", action: "rollback"
allow :engineer_prod_read,   "Engineers read prod", env: "prod", role: "engineer", action: "read"
allow :engineer_nonprod,     "Engineers work freely outside prod",
      env: %w[dev staging], role: "engineer"
allow :contractor_dev,       "Contractors work in dev", env: "dev", role: "contractor"
allow :everyone_reads,       "Anyone reads dev and staging",
      env: %w[dev staging], action: "read"
