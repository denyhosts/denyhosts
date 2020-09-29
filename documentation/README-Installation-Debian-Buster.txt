################################################
# Install DenyHosts from the Github repository #
################################################

This installation has been tested under Debian Buster Stable and is functional in most cases.
If the installation should not work, please report the errors encountered, so that we can make a correction.

The purpose of this documentation is to facilitate the deployment of the latest version of DenyHosts on Debian Buster.

Currently DenyHosts is not available in the Debian Buster Stable repositories and the version of DenyHosts supported by the Debian project is 2.10-2 available from the Debian SID repositories.
The version offered from the Github repository is 3.1.2-2 (or higher).

This documentation will certainly still evolve, nevertheless, it should allow, as it stands, to accompany you for a simplified installation of DenyHosts, without difficulties.

Version 2.0 proposed by Zer00CooL
Date : 02/06/2020

#################################################
# Packages required before installing DenyHosts #
#################################################

# The SSH server must be installed and configured.
# This is not the purpose of this documentation.
sudo apt install openssh-server

# Install the following package to be able to recover the project from Github using git :
# This is not the purpose of this documentation.
sudo apt-get install git

# The auth.log file is not always completed following an identification attempt by SSH, but, Denyhosts is based on this file!
sudo apt install rsyslog
sudo systemctl restart rsyslog
# Check if the /var/log/auth.log file exists to allow DenyHosts to restart :
cd /var/log
ls
# If it does not exist, create it :
sudo touch /var/log/auth.log

# Install the following python packages and modules:
sudo apt-get install python python3 python-pip
#
# The following 4 modules can be installed with a single line, allows compliance with version recommendations.
# sudo pip install ipaddr
# sudo pip install mock
# sudo pip install requests
# sudo pip install configparser
# This file is at the root of the DenyHosts repository and can be install later :
# pip install -r requirements.txt

# DenyHosts works with Iptables but is not a prerequisite.
# However, Iptables is enabled by default in the DenyHosts configuration.
# If you use the default configuration, it will be more consistent to install Iptables.
# sudo apt-get install iptables
#
# Denyhosts works without the Iptables package with TCP Wrapper.
# You can disable Iptables in the Denyhosts configuration.
# If this option is not set or commented out in the /etc/denyhosts.conf file, then the Iptables firewall is not used :
# IPTABLES = /sbin/iptables

# DenyHosts works with EXIM.
###############################################
# Think of the editor, need to be confirmed ! #
###############################################
# Check if EXIM is really an essential prerequisite. ( #155 )
# sudo apt-get install exim4-base exim4-config exim4-daemon-light

# Download Denyhosts from the master branch of Github.
# Note that I load Denyhosts in the user directory, but, it would be better to load it in the tmp/ directory
cd ~
sudo git clone https://github.com/denyhosts/denyhosts.git

# Using git allows developers and users the ability to test a new version or a bug fix.
# Currently and by default, you are using the stable master branch.
# Change the stable main branch to a developing branch.
# The following is an example of using the code associated with a bug designated as bug_128 on github.
cd ~/denyhosts
git checkout bug_128
# If you want to install the most recent version, then you can continue without having to take care of this step.

# Go to the DenyHosts directory and run the following commands :
cd ~/denyhosts
pip install -r requirements.txt
sudo python setup.py install
# We have detected that you have an existing config file, would you like to back it up ? [Y|N]:
# N for no :
N
sudo cp denyhosts.conf /etc
sudo cp daemon-control-dist daemon-control

# Edit the following configuration and replace the 3 lines according to your system configuration.
# The proposed lines should correspond to a standard installation of Debian Buster Stable.
sudo nano daemon-control

###############################################
#### Edit these to suit your configuration ####
###############################################
# DENYHOSTS_BIN = "/usr/sbin/denyhosts.py"
# DENYHOSTS_LOCK = "/run/denyhosts.pid"
# DENYHOSTS_CFG = "/etc/denyhosts.conf"

# The default values can (should) be replaced with the following values.

###############################################
# Think of the editor, need to be confirmed ! #
###############################################
# Keeping the sbin instead of the bin proposed in an old tutorial allowed me to make synchronization work:
DENYHOSTS_BIN = "/usr/sbin/denyhosts.py"
DENYHOSTS_LOCK = "/var/lock/subsys/denyhosts"
DENYHOSTS_CFG = "/etc/denyhosts.conf"

cd ~
sudo mv denyhosts /usr/share/
cd /usr/share/denyhosts/
sudo cp denyhosts.py /usr/sbin/
# In the tutorial used initially, denyhosts.py was copied to the /usr/bin directory, but, synchronization seems to work only if I put it in /usr/sbin/.
# Reload the daemons to use updated values in the event of a change in the configuration of the proposed paths :
sudo systemctl daemon-reload

###############################################
# This First possibility does not seem suitable or obsolete !
###############################################
# First possibility :
# The daemon-control is added in the /etc/init.d folder :
# cd /etc/init.d
# sudo ln -s /usr/share/denyhosts/daemon-control denyhosts
#
# Second possibility :
###############################################
# The good way :
###############################################
# It would be more consistent to add the denyhosts.service service to /etc/systemd/system/denyhosts.service from /usr/share/denyhosts/. (# 156)
# The service file is created in the format that SystemD can use.
# In both cases, the execution of denyhosts works correctly.
# Simply using the service method will prevent errors from occurring by saying that there are no execution levels or lsb problems.
# The service file must be added to /etc/systemd/system/denyhosts.service rather than adding it to /etc/init.d.
# Adding to /etc/systemd/system/ will allow denyhosts services to start working with the systemctl start denyhosts command.
cd /usr/share/denyhosts/
sudo cp /usr/share/denyhosts/denyhosts.service /etc/systemd/system/denyhosts.service

# Activate the denyhosts service :
sudo systemctl enable denyhosts

# Launch the denyhosts service :
systemctl start denyhosts

###############################################
# Think of the editor, need to be confirmed ! #
###############################################
# During the test, with the first possibility, the start command did not work..
# Currently prefer to launch with restart.
# This problem now seems to be corrected using the second possibility during installation.
# We were able to start previously with the start command.
# It is no longer necessary to start like this :
# sudo systemctl restart denyhosts
# We can now observe the status of Denyhosts :
sudo systemctl status denyhosts

# Copy the configuration proposed below, to strengthen the rules of Denyhosts.
# This following configuration is proposed in French by Zer00CooL (ZerooCool on Github).
# Edit the DenyHosts configuration file :
sudo nano /etc/denyhosts.conf

################################################################################################
# Beginning - The configuration from DenyHosts : sudo nano /etc/denyhosts.conf
################################################################################################
# Le fichier journal qui contient les informations de journalisation du serveur SSH.
# Identifier le fichier avec la commande : grep "sshd:" /var/log/*
SECURE_LOG = /var/log/auth.log
# Le fichier qui contient des informations d'accès restreint à l'hôte.
HOSTS_DENY = /etc/hosts.deny
# Ne jamais purger le fichier :
# PURGE_DENY =
# 'y' = years 'w' = weeks 'd' = days 'h' = hours 'm' = minutes
# Purger le fichier /etc/hosts.deny toutes les 4 semaines :
PURGE_DENY = 4w
# Si la valeur est définie un hôte bloqué sera purgé au moins autant de fois.
# Si cette valeur est définie sur 3, DenyHosts purgera un hôte au maximum 4 fois.
# Après que l'hôte ait été purgé 3 fois, l'hôte restera bloqué dans le HOSTS_DENY pour toujours.
# Si la valeur est définie sur 0, DenyHosts purgera chaque hôte indéfiniment sans le bloquer de façon permanente.
PURGE_THRESHOLD = 3
# Bloquer les tentatives d'intrusion avec l'option ALL empêchera le serveur ne répondre aux adresses IP attaquantes.
# Bloquer uniquement les attaques sur le serveur SSH avec la commande : BLOCK_SERVICE  = sshd
BLOCK_SERVICE = ALL
# Bloquer un hôte qui tente de se connecter avec un compte d'utilisateur inexistant après 2 tentatives.
DENY_THRESHOLD_INVALID = 2
# Bloquer un hôte qui tente de se connecter avec un compte d'utilisateur valide après 3 tentatives.
# L'utilisateur root n'est pas concerné.
DENY_THRESHOLD_VALID = 3
# Bloquer un hôte qui tente de se connecter avec le compte root après 1 tentative.
DENY_THRESHOLD_ROOT = 1
# Les utilisateurs dans le fichier d'utilisateurs restreints sont limités par DENY_THRESHOLD_RESTRICTED.
# Il est défini sur DENY_THRESHOLD_ROOT par défaut.
DENY_THRESHOLD_RESTRICTED = 1
# Le chemin absolu utilisé par DenyHosts pour écrire les données.
WORK_DIR = /var/lib/denyhosts
# Le chemin pour lire une configuration.
ETC_DIR = /etc
# Si une tentative de connexion suspecte résulte d'un hôte autorisé alors il est considéré comme suspect.
SUSPICIOUS_LOGIN_REPORT_ALLOWED_HOSTS=YES
# Bloquer le nom de l'hôte lorsque qu'il est possible de le récupérer.
HOSTNAME_LOOKUP=YES
# Verrouiller le fichier PID de DenyHosts pour qu'il y ait que une seule instance en fonctionnement.
LOCK_FILE = /run/denyhosts.pid
# Bloquer les connexions entrantes en utilisant le pare-feu Linux IPTABLES.
# Définir la variable vers le chemin de l'exécutable iptables "/sbin/iptables".
# Si cette option n'est pas définie ou commentée, le pare-feu n'est pas utilisé.
IPTABLES = /sbin/iptables
# Ne pas bloquer tous les ports avec ALL mais uniquement les ports indiqués.
# BLOCKPORT = 22
# Si iptables est renseigné et activé, désactiver les deux options suivantes.
# PFCTL_PATH = /sbin/pfctl
# PF_TABLE = blacklist
# Mail de l'administrateur à prévenir lors d'un nouveau blocage.
# Les mails de root peuvent être redirigés par le système.
ADMIN_EMAIL = root@localhost
# Hôte SMTP.
SMTP_HOST = localhost
# Port SMTP.
SMTP_PORT = 25
# Renseigner les paramètres suivants si le serveur SMTP nécessiste une authentification.
# SMTP_USERNAME=Username
# SMTP_PASSWORD=Password
# Mail émetteur du message.
SMTP_FROM = DenyHosts <nobody@localhost>
# Sujet du message.
SMTP_SUBJECT = DenyHosts Report
# Date du message.
SMTP_DATE_FORMAT = %a, %d %b %Y %H:%M:%S %z
# Activer la journalisation dans le fichier syslog.
SYSLOG_REPORT=YES
# Si la configuration du serveur SSH et tcp_wrappers enregistrent des noms d'hôtes plutôt que des adresses IP,
# DenyHosts peut résoudre chaque adresse IP du fichier hosts.allow pour déterminer le nom d'hôte correspondant.
# Tout hôte correspondant à cette adresse IP résolue ou au nom d'hôte ne sera pas bloqué.
# Si les noms d'hôtes n'apparaissent jamais dans le SECURE_LOG, définir ce paramètre sur NO.
ALLOWED_HOSTS_HOSTNAME_LOOKUP=NO
# Période pour la remise à zéro du compteur de tentative de connexion invalide, sauf pour l'utilisateur root.
AGE_RESET_VALID=4h
# Période pour la remise à zéro du compteur de tentative de connexion invalide pour l'utilisateur root.
AGE_RESET_ROOT=4w
# Période pour la remise à zéro du compteur de tentative de connexion invalide pour les utilisateurs dans le
# fichier "WORK_DIR/restricted-usernames".
AGE_RESET_RESTRICTED=4w
# Période pour la remise à zéro du compteur de tentative de connexion invalide pour les utilisateurs invalides.
# Ceux qui n'apparaissent pas dans "/etc/passwd".
AGE_RESET_INVALID=4w
# Le nombre d'échecs pour une adresse IP sera réinitialisé à 0 suite à une connexion réussie.
RESET_ON_SUCCESS = yes
# Si elle est définie, cette valeur doit pointer vers un programme exécutable qui sera invoqué lorsqu'un hôte sera
# ajouté au fichier HOSTS_DENY.
#PLUGIN_DENY=/usr/bin/true
# Si elle est définie, cette valeur doit pointer vers un programme exécutable qui sera invoqué lorsqu'un hôte sera
# supprimé au fichier HOSTS_DENY. 
#PLUGIN_PURGE=/usr/bin/true
# Si définie, cette valeur doit contenir une expression régulière qui peut être utilisée pour identifier des pirates
# pour votre configuration ssh particulière. Cette fonctionnalité étend les expressions régulières intégrées 
# utilisées par DenyHosts. Ce paramètre peut être spécifié plusieurs fois.
#USERDEF_FAILED_ENTRY_REGEX=
# Fichier journal utilise pour signaler l'état de DenyHosts en mode démon (--daemon).
# Laisser vide pour désactiver la journalisation.
DAEMON_LOG = /var/log/denyhosts
# Format de la date dans les logs.
DAEMON_LOG_TIME_FORMAT = %b %d %H:%M:%S
# Spécifie le format de message de chaque entrée de journal en mode démon (--daemon).
# Par défaut, le format suivant est utilisé :
#DAEMON_LOG_MESSAGE_FORMAT = %(asctime)s - %(name)-12s: %(levelname)-8s %(message)s
# Durée pendant laquelle DenyHosts dormira entre les interrogations en mode démon (--daemon).
# Valeur par défaut de 30s que je ralonge un peu pour économiser les ressources du système.
DAEMON_SLEEP = 1m
# Fréquence de purge en mode démon (--daemon).
DAEMON_PURGE = 1h
# Synchronisation entre plusieurs DenyHosts.
# Dès qu'un de vos serveurs subis une attaque, tous vos serveurs blacklistent cette adresse IP.
# Le serveur central qui communique avec le démon DenyHost.
# Pour activer la synchronisation, décommenter la ligne suivante :
SYNC_SERVER = http://xmlrpc.denyhosts.net:9911
# Activer un proxy HTTP.
#SYNC_PROXY_SERVER = http://mon.serveur.proxy:3128
# Intervale de temps entre chaque synchronisation.
SYNC_INTERVAL = 1h
# Autoriser le démon DenyHosts à transmettre des hôtes qui ont été refusé.
# Cette option ne s'applique que si SYNC_SERVER n'a pas été commenté.
SYNC_UPLOAD = yes
# Autoriser le démon DenyHosts à recevoir des hôtes qui ont été refusés par d'autres.
# Cette option ne s'applique que si SYNC_SERVER n'a pas été commenté.
SYNC_DOWNLOAD = yes
# Définir un filtre pour des adresses bloquées reçues par d'autres serveurs.
# Le chiffre indique le nombre de fois que l'adresse IP aura été bloquée au minimum.
SYNC_DOWNLOAD_THRESHOLD = 4
# Durée minimum de la période d'attaque observée sur d'autres serveurs.
SYNC_DOWNLOAD_RESILIENCY = 8h
################################################################################################
# End - The configuration from DenyHosts
################################################################################################

# Note for synchronization !
# The current synchronization servers :
# http://sync.denyhosts.org:9911
# http://deny.resonatingmedia.com:9911
#
# The old synchronization server :
# http://xmlrpc.denyhosts.net:9911
###############################################
# Think of the editor, need to be confirmed ! #
###############################################
# Old server, but, same content ?

# Restart Denyhosts to apply the new configuration.
# Deprecated commands :
sudo /etc/init.d/denyhosts restart
sudo service denyhosts restart
#
# Prefer this command to restart DenyHosts :
sudo systemctl restart denyhosts

