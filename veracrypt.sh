# install veracrypt if not exist
if ! [ -x "$(command -v veracrypt)" ]; then
	sudo apt-get install -y libfuse-dev makeself libwxbase3.0-0
	cd /tmp/
	wget https://launchpad.net/veracrypt/trunk/1.21/+download/veracrypt-1.21-raspbian-setup.tar.bz2
	tar -vxjf ./veracrypt-1.21-raspbian-setup.tar.bz2
	sudo chmod +x veracrypt-1.21-setup-*
	./veracrypt-1.21-setup-console-armv7
	sudo mkdir -p /var/www/owncloud/data
	sudo chown www-data:www-data /var/www/owncloud/data
fi
veracrypt -k "" --pim=0 -m=nokernelcrypto --protect-hidden=no /dev/sda1 /var/www/owncloud/data
