#/bin/sh

cp ../org.cryptable.eidonkey.json $HOME/Library/Application\ Support/Google/Chrome/NativeMessagingHosts
mkdir -p $HOME/.eidonkey
cp ../../../eidonkey/target/release/eidonkey $HOME/.eidonkey