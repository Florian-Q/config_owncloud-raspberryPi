#! /bin/bash


read -p "Enter your Domain name : " nameDomain


echo "--- Config SSH ---"
read -p "> Select port for connection ssh, 42 by default but it not secure
(port unassigned : 4, 6, 8, 10, 12, 14, 16, 26, 28, 30, 32, 34, 36, 40, 60) : " portSsh
while ! [ "$portSsh" -ge 1 -a "$portSsh" -le 65535 ]; do
	read -p "Please enter a number between 1-65535 : " portSsh
done

read -p "> Disable Password Authentication (if you have a key Authentication) [y/n] :" ynPassAuth
case $ynPassAuth in
    [Yyes]* ) 	passwordAuth="no";;
	* )			passwordAuth="yes";
esac

echo "Port $portSsh
Protocol 2
PermitRootLogin no
MaxSessions 1
#durée pendant laquelle une connexion sans être loggée sera ouverte
LoginGraceTime 30s
#nombre maximum d essais
MaxAuthTries 1
#nombre de connexions ssh non authentifiées en même temps
MaxStartups 1
#désactiver toutes les autres méthodes d authentification
RSAAuthentication no
UsePAM no
KerberosAuthentication no
GSSAPIAuthentication no
PasswordAuthentication $passwordAuth" | sudo tee --append /etc/ssh/sshd_config
echo "(add new option in : /etc/ssh/sshd_config)"


echo "--- Config database (MariaDB) ---"

read -p "> User database : " -i "owncloudUser" -e owncloudUser
read -p "> Password of user database : " -s owncloudBDPassword
read -p "> Name of database : " -i "owncloudDB" -e owncloudDB


echo "--- Config SSL ---"
sudo mkdir -p /etc/nginx/certs
read -p "> Do you want to generate an SSL certificate [y/n] :" ynSsl
    case $ynSsl in
        [Yyes]* )	cd /etc/nginx/certs/
					echo 'basicConstraints=CA:true' | sudo tee android_options.txt
					sudo openssl genrsa -out owncloud.key 4096
					sudo openssl req -new -key owncloud.key -out owncloud.csr
					sudo openssl x509 -req -days 3650 -in owncloud.csr -signkey owncloud.key -extfile ./android_options.txt -out owncloud.crt;;
 		* ) echo "Even if the SSL certificate is not generated, the Nginx web server needs a 'dhparam.pem' file in : /etc/nginx/certs/";
    esac


echo "--- Config No-Ip ---"
cd /tmp/
read -p "> Do you wish to install no-ip client for fix your IP [y/n] :" ynNoIP
    case $ynNoIP in
        [Yyes]* ) 	sudo wget https://www.noip.com/client/linux/noip-duc-linux.tar.gz
					sudo wget http://download.sizious.com/rpi/noip-duc-raspbian.tar.bz2
					cd /usr/local/src/
					sudo tar xf /tmp/noip-duc-linux.tar.gz
					sudo tar -xjvf /tmp/noip-duc-raspbian.tar.bz2
					cd noip-*/
					sudo make install
					sudo chmod +x raspbian.noip2.sh service.install.sh service.uninstall.sh
					sudo ./service.install.sh raspbian;;
 		* ) echo "Not install No-ip.";
    esac

echo "--- SART ---"
echo "-- Add depot"
cd /tmp/
# Add depot php7
echo "- php7"
sudo wget -O /etc/apt/trusted.gpg.d/php.gpg https://packages.sury.org/php/apt.gpg
echo 'deb https://packages.sury.org/php/ jessie main' | sudo tee /etc/apt/sources.list.d/php.list
# Add depot owncloud
echo "- owncloud for Debian_9"
sudo wget -nv https://download.owncloud.org/download/repositories/production/Debian_9.0/Release.key -O Release.key
sudo apt-key add - < Release.key
echo 'deb http://download.owncloud.org/download/repositories/production/Debian_9.0/ /' | sudo tee /etc/apt/sources.list.d/owncloud.list


echo "-- Update package"
sudo apt update -y; sudo apt full-upgrade -y


echo "-- Install package"
#Automatic updates
echo "- unattended-upgrades"
sudo apt-get install -y unattended-upgrades
echo "- php7"
sudo apt-get install -y php7.0-mysql php7.0-fpm php7.0-curl php7.0-xml php7.0-json php7.0-zip php7.0-mb php7.0-mcrypt php7.0-gd
#PATH php configuration
sudo sed -i -e "s/;env\[PATH\]/env\[PATH\]/g" /etc/php/7.0/fpm/pool.d/www.conf
echo "- redis"
sudo apt-get install -y redis-server php-redis
#database
echo "- mariadb"
sudo apt-get install -y mariadb-server mariadb-client
echo "- owncloud"
sudo apt-get install -y owncloud-files
#web server
echo "- nginx"
sudo apt-get install -y nginx


echo "-- Database configuration"
## Execute queries manually of mysql_secure_installation script
# Make sure that NOBODY can access the server without a password
#mysql -e "UPDATE mysql.user SET Password = PASSWORD('CHANGEME') WHERE User = 'root'"
# Kill the anonymous users
mysql -e "DROP USER ''@'localhost'"
# Because our hostname varies we'll use some Bash magic here.
mysql -e "DROP USER ''@'$(hostname)'"
# Kill off the demo database
mysql -e "DROP DATABASE test"
# Make our changes take effect
mysql -e "FLUSH PRIVILEGES"
# Any subsequent tries to run queries this way will get access denied because lack of usr/pwd param

sudo mysql -u root -e "CREATE DATABASE IF NOT EXISTS $owncloudDB;
DROP USER IF EXISTS $owncloudUser@localhost;
CREATE USER '$owncloudUser'@'localhost' IDENTIFIED BY '$owncloudBDPassword';
GRANT ALL ON $owncloudDB.* TO '$owncloudUser'@'localhost' IDENTIFIED BY '$owncloudBDPassword' WITH GRANT OPTION; 
FLUSH PRIVILEGES;"


echo "-- Redis configuration in owncloud"
sudo -u www-data php /var/www/owncloud/occ config:system:set filelocking.enabled --value=true
sudo -u www-data php /var/www/owncloud/occ config:system:set memcache.local --value='\OC\Memcache\Redis'
sudo -u www-data php /var/www/owncloud/occ config:system:set memcache.locking --value='\OC\Memcache\Redis'
sudo -u www-data php /var/www/owncloud/occ config:system:set redis host --value=localhost
sudo -u www-data php /var/www/owncloud/occ config:system:set redis port --value=6379


echo "-- Nginx configuration"
## create config to launch owncloud site
echo 'upstream php-handler {
    server 127.0.0.1:9000;
    server unix:/var/run/php/php7.0-fpm.sock;
}

server {
    listen 443 ssl http2;
    server_name '$nameDomain';

    # Parametres pour SSL/TLS
    ssl_certificate /etc/nginx/certs/owncloud.crt;
    ssl_certificate_key /etc/nginx/certs/owncloud.key;
    ssl_dhparam /etc/nginx/certs/dhparam.pem;

    # Add headers to serve security related headers
    # Before enabling Strict-Transport-Security headers please read into this topic first.
    add_header Strict-Transport-Security "max-age=15552000; includeSubDomains";
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-XSS-Protection "1; mode=block";
    add_header X-Robots-Tag none;
    add_header X-Download-Options noopen;
    add_header X-Permitted-Cross-Domain-Policies none;

    # Path to the root of your installation
    root /var/www/owncloud/;

    location = /robots.txt {
        allow all;
        log_not_found off;
        access_log off;
    }

    # The following 2 rules are only needed for the user_webfinger app.
    # Uncomment it if you are planning to use this app.
    #rewrite ^/.well-known/host-meta /public.php?service=host-meta last;
    #rewrite ^/.well-known/host-meta.json /public.php?service=host-meta-json last;

    location = /.well-known/carddav {
        return 301 $scheme://$host/remote.php/dav;
    }
    location = /.well-known/caldav {
        return 301 $scheme://$host/remote.php/dav;
    }

    # Disable gzip to avoid the removal of the ETag header
    # Enabling gzip would also make your server vulnerable to BREACH
    # if no additional measures are done. See https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=773332
    gzip off;

    error_page 403 /core/templates/403.php;
    error_page 404 /core/templates/404.php;

    location / {
        rewrite ^ /index.php$uri;
    }

    location ~ ^/(?:build|tests|config|lib|3rdparty|templates|data)/ {
        return 404;
    }
    location ~ ^/(?:\.|autotest|occ|issue|indie|db_|console) {
        return 404;
    }

    location ~ ^/(?:index|remote|public|cron|core/ajax/update|status|ocs/v[12]|updater/.+|ocs-provider/.+|core/templates/40[34])\.php(?:$|/) {
        fastcgi_split_path_info ^(.+\.php)(/.*)$;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_param SCRIPT_NAME $fastcgi_script_name; # necessary for owncloud to detect the contextroot https://github.com/owncloud/core/blob/v10.0.0/lib/private/AppFramework/Http/Request.php#L603
        fastcgi_param PATH_INFO $fastcgi_path_info;
        fastcgi_param HTTPS on;
        fastcgi_param modHeadersAvailable true; #Avoid sending the security headers twice
        fastcgi_param front_controller_active true;
        fastcgi_read_timeout 180; # increase default timeout e.g. for long running carddav/ caldav syncs with 1000+ entries
        fastcgi_pass php-handler;
        fastcgi_intercept_errors on;
        fastcgi_request_buffering off; #Available since NGINX 1.7.11
    }

  location ~ ^/(?:updater|ocs-provider)(?:$|/) {
        try_files $uri $uri/ =404;
        index index.php;
    }

    # Adding the cache control header for js and css files
    # Make sure it is BELOW the PHP block
    location ~ \.(?:css|js)$ {
        try_files $uri /index.php$uri$is_args$args;
        add_header Cache-Control "max-age=15778463";
        # Add headers to serve security related headers (It is intended to have those duplicated to the ones above)
        # Before enabling Strict-Transport-Security headers please read into this topic first.
        #add_header Strict-Transport-Security "max-age=15552000; includeSubDomains";
        add_header X-Content-Type-Options nosniff;
        add_header X-Frame-Options "SAMEORIGIN";
        add_header X-XSS-Protection "1; mode=block";
        add_header X-Robots-Tag none;
        add_header X-Download-Options noopen;
        add_header X-Permitted-Cross-Domain-Policies none;
        # Optional: Dont log access to assets
        access_log off;
    }

    location ~ \.(?:svg|gif|png|html|ttf|woff|ico|jpg|jpeg|map)$ {
        add_header Cache-Control "public, max-age=7200";
        try_files $uri /index.php$uri$is_args$args;
        # Optional: Dont log access to other assets
        access_log off;
    }
}' | sudo tee /etc/nginx/sites-available/owncloud
# active le site
sudo ln -s /etc/nginx/sites-available/owncloud /etc/nginx/sites-enabled/


# Generate SSL certificate
case $ynSsl in
	[Yyes]* )	echo "-- Generate SSL certificate"
				echo "(can last a really long time)"
				cd /etc/nginx/certs/
				sudo openssl dhparam -out dhparam.pem 4096
esac


# echo "-- Upgrade firmware"
# sudo rpi-update # reboot after


echo "--- End ---"