To indicate which vaulted credential to retrieve from CyberArk vault, specify account name and safe name in the Vault Config using following json format.

{"accountname":"<the vaulted account name in CyberArk>","safename":"<The safe name for the vaulted account>", "ignoreMapping":["accountname","safename"]}
