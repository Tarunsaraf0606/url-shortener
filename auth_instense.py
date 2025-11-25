from auth.Auth import ProductionAuthLayer

auth = ProductionAuthLayer.from_env(use_redis=False, multi_tenant=False)

