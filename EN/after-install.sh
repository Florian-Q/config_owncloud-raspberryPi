echo "-- Redis configuration in owncloud"
sudo -u www-data php /var/www/owncloud/occ config:system:set filelocking.enabled --value=true
sudo -u www-data php /var/www/owncloud/occ config:system:set memcache.local --value='\OC\Memcache\Redis'
sudo -u www-data php /var/www/owncloud/occ config:system:set memcache.locking --value='\OC\Memcache\Redis'
sudo -u www-data php /var/www/owncloud/occ config:system:set redis host --value=localhost
sudo -u www-data php /var/www/owncloud/occ config:system:set redis port --value=6379

echo "-- Scan new files in /var/www/owncloud/data/"
sudo -u www-data php /var/www/owncloud/occ files:scan 