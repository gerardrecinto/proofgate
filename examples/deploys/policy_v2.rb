# Same policy after a "tidy-up": rules grouped by role, the prod delete freeze folded away.
policy_name "deploys"

dimension :env,      %w[dev staging prod]
dimension :role,     %w[engineer sre contractor]
dimension :action,   %w[read deploy rollback delete]
dimension :approved, %w[yes no]

never  :no_contractor_prod,  "Contractors never change prod",
       env: "prod", role: "contractor", action: %w[deploy rollback delete]
never  :no_unapproved_prod,  "Nothing is deployed or deleted in prod without approval",
       env: "prod", action: %w[deploy delete], approved: "no"
always :sre_can_roll_back,   "SREs can always roll back",
       role: "sre", action: "rollback"

allow :sre_rollback,         "SREs roll back anywhere", role: "sre", action: "rollback"
allow :sre_prod,             "SREs run prod with approval",
      env: "prod", role: "sre", approved: "yes"
allow :engineer_prod_read,   "Engineers read prod", env: "prod", role: "engineer", action: "read"
allow :engineer_nonprod,     "Engineers work freely outside prod",
      env: %w[dev staging], role: "engineer"
allow :contractor_env,       "Contractors work outside prod",
      env: %w[dev staging], role: "contractor"
allow :everyone_reads,       "Anyone reads dev and staging",
      env: %w[dev staging], action: "read"
