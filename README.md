# TruSecrets

Really simple secrets management tool built for other projects, useful if you don't want to pay for more sophisticated solutions

## Setup
First run the install script with
```
sudo bash install.sh
```

Then run
```
./secrets_manager
```

## Usage
When running secrets_manager, first enter a master password. Remember it, as it is basically a namespace that you'll need for all secrets within it.

Store:
```
dev@development:~/dev/TruSecrets$ ./secrets_manager 
Enter your master password: test_master
Enter command (store/get/exit): store
Enter secret name: test_secret
Enter secret value: secret_value
Secret stored.
```

Get:
```
dev@development:~/dev/TruSecrets$ ./secrets_manager 
Enter your master password: test_master
Enter command (store/get/exit): get
Enter secret name: test_secret
Secret: secret_value
```