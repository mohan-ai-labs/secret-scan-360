# Azure SAS tokens with past expiry dates - SYNTHETIC EXAMPLES
# ⚠️ FAKE EXPIRED TOKENS FOR TESTING ONLY ⚠️

# Expired Azure Storage SAS URL (expired 2022-01-01)
EXPIRED_AZURE_SAS_1 = "https://mystorageaccount.blob.core.windows.net/mycontainer?sv=2020-08-04&ss=bfqt&srt=sco&sp=rwdlacupx&se=2022-01-01T00:00:00Z&st=2021-01-01T00:00:00Z&spr=https&sig=fakesignatureforexpiredtestingonly"

# Another expired SAS (expired 2021-12-31) 
EXPIRED_AZURE_SAS_2 = "https://testaccount.blob.core.windows.net/uploads?sv=2019-12-12&se=2021-12-31T23%3A59%3A59Z&sr=c&sp=racwdl&sig=anotherfakeexpiredsignatureexample"

class AzureConfig:
    """Azure configuration with expired SAS tokens"""
    
    # Storage account SAS that expired in early 2022
    STORAGE_SAS = "https://prodstorageaccount.blob.core.windows.net/data?sv=2020-02-10&se=2022-03-01T00%3A00%3A00Z&sr=c&sp=rl&sig=fakeexpiredstoragesignature"
    
    # Backup storage SAS (also expired)
    BACKUP_SAS = "https://backupstorage.blob.core.windows.net/backups?sv=2019-07-07&se=2021-12-31T23%3A59%3A59Z&sr=c&sp=r&sig=expiredbackupsignaturefake"

# Historical Azure credentials (fake/expired)
LEGACY_AZURE_KEYS = [
    "https://oldaccount.blob.core.windows.net/legacy?se=2021-01-01T00%3A00%3A00Z&sig=oldexpiredsig",
    "https://deprecatedstg.blob.core.windows.net/archive?se=2020-12-31T23%3A59%3A59Z&sig=deprecatedexpiredsig"
]