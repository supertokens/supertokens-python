def pytest_configure():
    import os
    os.environ.setdefault('SUPERTOKENS_ENV', 'testing')
    os.environ.setdefault('SUPERTOKENS_PATH', '../supertokens-root')
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tests.Django.settings')
