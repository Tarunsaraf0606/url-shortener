from auth.Auth import ProductionAuthLayer

auth = ProductionAuthLayer.from_env(use_redis=True, multi_tenant=False)

