import sys
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QPushButton, QVBoxLayout, QGridLayout, QLineEdit, QComboBox, QTextEdit, QTableWidget, QTableWidgetItem, QMessageBox, QProgressBar, QGroupBox, QCheckBox, QSpinBox
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QRectF
from PyQt5.QtGui import QFont, QColor, QPainter, QPen
import socket
import threading
import time
import logging
import nmap
from scapy.all import *
from urllib.request import urlopen
from bs4 import BeautifulSoup
import json
import re
import subprocess
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import psutil

# Configuration du journal de surveillance des événements
logging.basicConfig(filename='intrusion_log.txt', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration par défaut des règles d'anomalies
regles_anomalies = {
    'ports_vulnerables': [22, 80, 443, 3306],  # Ports courants vulnérables
    'frequence_connexion': 10,  # Limite de connexions par seconde
    'taille_paquet_suspecte': 1024,  # Limite de la taille des paquets
    'frequence_erreurs': 5, # Limite d'erreurs par seconde
    'frequence_tentatives_connexion': 10,  # Limite de tentatives de connexion par seconde
}

# Configuration des sources de données de vulnérabilités
sources_vulnerabilites = {
    'exploit-db': 'https://www.exploit-db.com/',
    'vuldb': 'https://vuldb.com/',
    'cvedetails': 'https://www.cvedetails.com/',
    'nvd': 'https://nvd.nist.gov/'
}

# Configuration de l'apprentissage automatique
config_apprentissage_automatique = {
    'activer': False,  # Activer/désactiver l'apprentissage automatique
    'nombre_d_arbres': 100,  # Nombre d'arbres dans la forêt d'isolation
    'contamination': 0.1,  # Pourcentage de données considérées comme anormales
}

# Configuration de la protection proactive
config_protection_proactive = {
    'activer': False,  # Activer/désactiver la protection proactive
    'bloquer_adresses_ip': False,  # Bloquer les adresses IP suspectes
    'mettre_en_quarantaine_fichiers': False,  # Mettre en quarantaine les fichiers suspects
    'redémarrer_services': False,  # Redémarrer les services suspects
}

# Fonction pour exécuter une commande shell en tant que root
def executer_commande_root(commande):
    try:
        process = subprocess.run(commande, shell=True, check=True)
        return process.stdout.decode('utf-8')
    except subprocess.CalledProcessError as e:
        logging.error(f"Erreur lors de l'exécution de la commande: {e}")
        return None

# Fonction pour obtenir l'adresse IP de l'interface réseau
def obtenir_adresse_ip(interface):
    try:
        output = executer_commande_root(f"ip addr show dev {interface} | grep 'inet ' | awk '{{print $2}}'")
        if output:
            return output.strip()
        else:
            return None
    except Exception as e:
        logging.error(f"Erreur lors de l'obtention de l'adresse IP: {e}")
        return None

# Fonction pour scanner le réseau local
def scanner_reseau(adresse_reseau='192.168.1.0/24'):
    nm = nmap.PortScanner()
    nm.scan(hosts=adresse_reseau, arguments='-T4 -F')  # Scanner les adresses IP du réseau local
    machines_disponibles = {}
    for ip in nm.all_hosts():
        services = []
        for proto in nm[ip]['tcp']:
            services.append(f"{proto}/{nm[ip]['tcp'][proto]['name']}")
        machines_disponibles[ip] = services
    return machines_disponibles

# Fonction pour rechercher des vulnérabilités dans une base de données
def rechercher_vulnerabilites(machine):
    """Recherche des vulnérabilités connues pour les services en cours d'exécution sur la machine.

    Args:
        machine (dict): Informations sur la machine cible.

    Returns:
        list: Liste des vulnérabilités trouvées.
    """
    vulnerabilites = []
    for service in machine.values():
        for source in sources_vulnerabilites.values():
            try:
                # Extraire les informations de vulnérabilité de la source de données
                # (A adapter selon la structure du site web)
                page = urlopen(source)
                soup = BeautifulSoup(page, 'html.parser')
                # ... (Extraire les informations de vulnérabilité)
                # ... (Ajouter les vulnérabilités à la liste)
            except Exception as e:
                logging.error(f"Erreur lors de la recherche de vulnérabilités: {e}")
    return vulnerabilites

# Classe pour gérer la surveillance du serveur en arrière-plan
class SurveillanceServeur(QThread):
    signal_alerte = pyqtSignal(str)  # Signal pour envoyer des alertes à l'interface
    signal_mise_a_jour_table = pyqtSignal(list)  # Signal pour mettre à jour le tableau des machines
    signal_mise_a_jour_graphique = pyqtSignal(list)  # Signal pour mettre à jour le graphique de trafic

    def __init__(self, adresse_serveur, regles, machine):
        super().__init__()
        self.adresse_serveur = adresse_serveur
        self.regles = regles
        self.machine = machine
        self.timer_analyse_vulnerabilites = QTimer()
        self.timer_analyse_vulnerabilites.timeout.connect(self.analyser_vulnerabilites)
        self.timer_analyse_vulnerabilites.start(60000)  # Analyse des vulnérabilités toutes les minutes
        self.data_trafic = []
        self.modele_apprentissage_automatique = None
        self.scaler = StandardScaler()
        self.initialiser_apprentissage_automatique()
        self.dernier_log = time.time()

    def run(self):
        try:
            # Création d'une socket pour écouter les connexions entrantes
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(self.adresse_serveur)
            s.listen(5)
            logging.info(f"Surveillance du trafic du serveur: {self.adresse_serveur}")
        except Exception as e:
            logging.error(f"Erreur lors de la création de la socket: {e}")
            return

        while True:
            # Attente d'une nouvelle connexion
            connexion, adresse_client = s.accept()
            logging.info(f"Nouvelle connexion: {adresse_client}")

            # Création d'un thread pour gérer la connexion
            thread_connexion = threading.Thread(target=self.gerer_connexion, args=(connexion, adresse_client))
            thread_connexion.start()

    def gerer_connexion(self, connexion, adresse_client):
        """Gère une connexion entrante et analyse le trafic.

        Args:
            connexion (socket): Socket de la connexion.
            adresse_client (tuple): Adresse IP et port du client.
        """
        try:
            derniere_connexion = time.time()
            derniere_erreur = time.time()
            derniere_tentative_connexion = time.time()
            while True:
                # Réception des données du client
                data = connexion.recv(1024)
                if not data:
                    break  # Fin de la connexion
                logging.info(f"Données reçues de {adresse_client}: {data}")

                # Analyse des données pour détecter des anomalies
                if self.analyser_paquet(data, adresse_client):
                    # En cas d'anomalie détectée, envoyer une alerte
                    logging.info(f"Alerte! Anomalie détectée: {adresse_client} - {data.decode()}")
                    self.signal_alerte.emit(f"Alerte! Anomalie détectée: {adresse_client} - {data.decode()}")

                    # Protection proactive
                    if config_protection_proactive['activer']:
                        self.appliquer_protection_proactive(adresse_client)

                # Enregistrer les données du trafic pour l'apprentissage automatique
                self.enregistrer_trafic(data, adresse_client)

                # Enregistrer des logs toutes les 20 secondes
                if time.time() - self.dernier_log > 20:
                    self.enregistrer_logs()
                    self.dernier_log = time.time()

        except Exception as e:
            logging.error(f"Erreur lors de la gestion de la connexion: {e}")
        finally:
            # Fermeture de la connexion
            connexion.close()

    def analyser_paquet(self, data, adresse_client):
        """Analyse les données du paquet pour détecter des anomalies.

        Args:
            data (bytes): Données reçues du client.
            adresse_client (tuple): Adresse IP et port du client.

        Returns:
            bool: True si une anomalie est détectée, False sinon.
        """
        global derniere_connexion, derniere_erreur, derniere_tentative_connexion
        # Vérification des ports utilisés pour la connexion
        if adresse_client[1] in self.regles['ports_vulnerables']:
            logging.info(f"Connexion détectée sur un port vulnérable: {adresse_client[1]}")
            return True

        # Vérification de la fréquence des connexions
        if time.time() - derniere_connexion < 1 / self.regles['frequence_connexion']:
            logging.info(f"Fréquence de connexion élevée détectée: {adresse_client}")
            return True
        derniere_connexion = time.time()

        # Vérification de la taille des paquets
        if len(data) > self.regles['taille_paquet_suspecte']:
            logging.info(f"Paquet de grande taille détecté: {adresse_client}")
            return True

        # Vérification de la fréquence d'erreurs (ex: tentatives d'accès à des ressources inexistantes)
        if 'Erreur' in data.decode() and time.time() - derniere_erreur < 1 / self.regles['frequence_erreurs']:
            logging.info(f"Fréquence d'erreurs élevée détectée: {adresse_client}")
            return True
        derniere_erreur = time.time()

        # Vérification de la fréquence des tentatives de connexion
        if 'connexion' in data.decode().lower() and time.time() - derniere_tentative_connexion < 1 / self.regles['frequence_tentatives_connexion']:
            logging.info(f"Fréquence de tentatives de connexion élevée détectée: {adresse_client}")
            return True
        derniere_tentative_connexion = time.time()

        # Vérification de la présence de mots clés suspects (ex: 'admin', 'password')
        if any(mot_cle in data.decode() for mot_cle in ['admin', 'password', 'root']):
            logging.info(f"Mots clés suspects détectés: {adresse_client} - {data.decode()}")
            return True

        # Analyse basée sur l'apprentissage automatique
        if config_apprentissage_automatique['activer']:
            if self.modele_apprentissage_automatique:
                anomaly_score = self.modele_apprentissage_automatique.score_samples(self.scaler.transform([[len(data), time.time() - derniere_connexion]]))
                if anomaly_score[0] < -2:
                    logging.info(f"Anomalie détectée par l'apprentissage automatique: {adresse_client} - {data.decode()}")
                    return True

        return False

    def enregistrer_trafic(self, data, adresse_client):
        """Enregistre les données du trafic pour l'apprentissage automatique."""
        self.data_trafic.append([len(data), time.time(), adresse_client])
        if len(self.data_trafic) > 100:  # Limiter la taille du buffer
            self.data_trafic = self.data_trafic[1:]
        self.signal_mise_a_jour_graphique.emit(self.data_trafic)

    def initialiser_apprentissage_automatique(self):
        """Initialise le modèle d'apprentissage automatique."""
        if config_apprentissage_automatique['activer']:
            self.modele_apprentissage_automatique = IsolationForest(n_estimators=config_apprentissage_automatique['nombre_d_arbres'], contamination=config_apprentissage_automatique['contamination'])
            if len(self.data_trafic) > 10:  # Entraîner le modèle si suffisamment de données sont disponibles
                df = pd.DataFrame(self.data_trafic, columns=['taille_paquet', 'timestamp', 'adresse_client'])
                self.modele_apprentissage_automatique.fit(self.scaler.fit_transform(df[['taille_paquet', 'timestamp']]))

    def analyser_vulnerabilites(self):
        """Analyse les vulnérabilités des machines surveillées."""
        if self.machine:
            vulnerabilites = rechercher_vulnerabilites(self.machine)
            if vulnerabilites:
                # Envoyer les informations de vulnérabilités à l'interface utilisateur
                self.signal_mise_a_jour_table.emit(vulnerabilites)

    def appliquer_protection_proactive(self, adresse_client):
        """Applique des actions de protection proactive."""
        if config_protection_proactive['bloquer_adresses_ip']:
            self.bloquer_adresse_ip(adresse_client)
        if config_protection_proactive['mettre_en_quarantaine_fichiers']:
            self.mettre_en_quarantaine_fichiers(adresse_client)
        if config_protection_proactive['redémarrer_services']:
            self.redémarrer_services(adresse_client)

    def bloquer_adresse_ip(self, adresse_client):
        """Bloque l'adresse IP suspecte."""
        # Implémenter la logique de blocage de l'adresse IP (ex: utiliser iptables)
        logging.info(f"Blocage de l'adresse IP: {adresse_client}")

    def mettre_en_quarantaine_fichiers(self, adresse_client):
        """Met en quarantaine les fichiers suspects associés à l'adresse IP."""
        # Implémenter la logique de mise en quarantaine des fichiers (ex: déplacer les fichiers dans un répertoire spécifique)
        logging.info(f"Mise en quarantaine des fichiers: {adresse_client}")

    def redémarrer_services(self, adresse_client):
        """Redémarre les services suspects associés à l'adresse IP."""
        # Implémenter la logique de redémarrage des services (ex: utiliser systemctl)
        logging.info(f"Redémarrage des services: {adresse_client}")

    def enregistrer_logs(self):
        """Enregistre les logs d'activité."""
        logging.info("Enregistrement des logs d'activité")

# Classe de la fenêtre principale de l'interface graphique
class FenetrePrincipale(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Système de Détection d'Intrusions (IDS)")
        self.setGeometry(100, 100, 1000, 700)  # Augmenter la taille de la fenêtre

        # Configuration du style
        self.setStyleSheet("""
            QWidget {
                background-color: #282c34; /* Fond sombre */
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; /* Police élégante */
                color: #d4d4d4; /* Couleur du texte clair */
            }

            QLabel {
                font-weight: bold; /* Texte en gras */
            }

            QPushButton {
                background-color: #4CAF50; /* Vert clair */
                color: white;
                padding: 10px 20px;
                border: none;
                border-radius: 5px;
                font-weight: bold;
            }

            QPushButton:hover {
                background-color: #3e8e41; /* Vert plus foncé au survol */
            }

            QPushButton:disabled {
                background-color: #607d8b; /* Gris foncé pour les boutons désactivés */
            }

            QLineEdit {
                background-color: #303030; /* Gris foncé pour les champs de texte */
                color: white;
                padding: 5px;
                border: 1px solid #424242; /* Bordure grise */
                border-radius: 3px;
            }

            QLineEdit:focus {
                border: 1px solid #4CAF50; /* Bordure verte au focus */
            }

            QTextEdit {
                background-color: #303030; /* Gris foncé pour la zone de texte */
                color: white;
                padding: 5px;
                border: 1px solid #424242; /* Bordure grise */
                border-radius: 3px;
            }

            QTableWidget {
                background-color: #303030; /* Gris foncé pour le tableau */
                color: white;
                border: 1px solid #424242; /* Bordure grise */
                border-radius: 3px;
            }

            QTableWidget::item {
                border: 1px solid #424242; /* Bordure grise pour les cellules */
                padding: 5px;
            }

            QTableWidget::item:selected {
                background-color: #4CAF50; /* Vert clair pour les cellules sélectionnées */
                color: white;
            }

            QGroupBox {
                background-color: #303030; /* Gris foncé pour le groupe de boîtes */
                border: 1px solid #424242; /* Bordure grise */
                border-radius: 3px;
            }

            QSpinBox {
                background-color: #303030; /* Gris foncé pour la boîte de rotation */
                color: white;
                border: 1px solid #424242; /* Bordure grise */
                border-radius: 3px;
            }

            QSpinBox::up-button, QSpinBox::down-button {
                background-color: #4CAF50; /* Vert clair pour les boutons */
                color: white;
                border: none;
                border-radius: 3px;
            }

            QSpinBox::up-button:hover, QSpinBox::down-button:hover {
                background-color: #3e8e41; /* Vert plus foncé au survol */
            }
        """)

        # Layout principal
        layout = QGridLayout()

        # Zone d'état
        zone_etat = QVBoxLayout()
        self.label_etat = QLabel("Système en cours d'exécution...")
        self.label_etat.setStyleSheet("font-size: 18px; font-weight: bold; color: green;")
        zone_etat.addWidget(self.label_etat)

        # Zone d'informations du système
        zone_info_systeme = QVBoxLayout()
        self.label_info_systeme = QLabel("Informations du système")
        self.label_info_systeme.setStyleSheet("font-size: 16px; font-weight: bold; color: #d4d4d4;")
        zone_info_systeme.addWidget(self.label_info_systeme)

        self.zone_texte_info_systeme = QTextEdit()
        self.zone_texte_info_systeme.setReadOnly(True)
        zone_info_systeme.addWidget(self.zone_texte_info_systeme)

        # Zone d'alertes
        zone_alertes = QVBoxLayout()
        self.zone_texte_alertes = QTextEdit()
        self.zone_texte_alertes.setReadOnly(True)
        zone_alertes.addWidget(self.zone_texte_alertes)

        # Zone de configuration
        zone_config = QVBoxLayout()
        self.label_ports = QLabel("Ports vulnérables (séparés par des virgules):")
        self.zone_ports = QLineEdit()
        self.zone_ports.setText(", ".join(str(port) for port in regles_anomalies['ports_vulnerables']))
        zone_config.addWidget(self.label_ports)
        zone_config.addWidget(self.zone_ports)

        self.label_frequence = QLabel("Fréquence de connexion (par seconde):")
        self.zone_frequence = QLineEdit()
        self.zone_frequence.setText(str(regles_anomalies['frequence_connexion']))
        zone_config.addWidget(self.label_frequence)
        zone_config.addWidget(self.zone_frequence)

        self.label_taille_paquet = QLabel("Taille de paquet suspecte (octets):")
        self.zone_taille_paquet = QLineEdit()
        self.zone_taille_paquet.setText(str(regles_anomalies['taille_paquet_suspecte']))
        zone_config.addWidget(self.label_taille_paquet)
        zone_config.addWidget(self.zone_taille_paquet)

        # Groupe de boîtes pour la configuration de l'apprentissage automatique
        groupe_apprentissage_automatique = QGroupBox("Apprentissage automatique")
        layout_apprentissage_automatique = QVBoxLayout()

        self.check_apprentissage_automatique = QCheckBox("Activer l'apprentissage automatique")
        self.check_apprentissage_automatique.setChecked(config_apprentissage_automatique['activer'])
        layout_apprentissage_automatique.addWidget(self.check_apprentissage_automatique)

        self.label_nombre_d_arbres = QLabel("Nombre d'arbres:")
        layout_apprentissage_automatique.addWidget(self.label_nombre_d_arbres)
        self.spin_nombre_d_arbres = QSpinBox()
        self.spin_nombre_d_arbres.setValue(config_apprentissage_automatique['nombre_d_arbres'])
        self.spin_nombre_d_arbres.setMinimum(10)
        self.spin_nombre_d_arbres.setMaximum(500)
        layout_apprentissage_automatique.addWidget(self.spin_nombre_d_arbres)

        self.label_contamination = QLabel("Pourcentage de contamination:")
        layout_apprentissage_automatique.addWidget(self.label_contamination)
        self.spin_contamination = QSpinBox()
        self.spin_contamination.setValue(int(config_apprentissage_automatique['contamination'] * 100))
        self.spin_contamination.setMinimum(1)
        self.spin_contamination.setMaximum(50)
        layout_apprentissage_automatique.addWidget(self.spin_contamination)

        groupe_apprentissage_automatique.setLayout(layout_apprentissage_automatique)
        zone_config.addWidget(groupe_apprentissage_automatique)

        # Groupe de boîtes pour la configuration de la protection proactive
        groupe_protection_proactive = QGroupBox("Protection proactive")
        layout_protection_proactive = QVBoxLayout()

        self.check_protection_proactive = QCheckBox("Activer la protection proactive")
        self.check_protection_proactive.setChecked(config_protection_proactive['activer'])
        layout_protection_proactive.addWidget(self.check_protection_proactive)

        self.check_bloquer_adresses_ip = QCheckBox("Bloquer les adresses IP suspectes")
        self.check_bloquer_adresses_ip.setChecked(config_protection_proactive['bloquer_adresses_ip'])
        layout_protection_proactive.addWidget(self.check_bloquer_adresses_ip)

        self.check_mettre_en_quarantaine_fichiers = QCheckBox("Mettre en quarantaine les fichiers suspects")
        self.check_mettre_en_quarantaine_fichiers.setChecked(config_protection_proactive['mettre_en_quarantaine_fichiers'])
        layout_protection_proactive.addWidget(self.check_mettre_en_quarantaine_fichiers)

        self.check_redémarrer_services = QCheckBox("Redémarrer les services suspects")
        self.check_redémarrer_services.setChecked(config_protection_proactive['redémarrer_services'])
        layout_protection_proactive.addWidget(self.check_redémarrer_services)

        groupe_protection_proactive.setLayout(layout_protection_proactive)
        zone_config.addWidget(groupe_protection_proactive)

        # Bouton "Démarrer la surveillance"
        self.bouton_demarrer = QPushButton("Démarrer la surveillance")
        self.bouton_demarrer.setStyleSheet("background-color: #4CAF50; color: white; padding: 10px 20px; border: none; border-radius: 5px;")
        self.bouton_demarrer.clicked.connect(self.demarrer_surveillance)

        # Bouton "Arrêter la surveillance"
        self.bouton_arreter = QPushButton("Arrêter la surveillance")
        self.bouton_arreter.setStyleSheet("background-color: #f44336; color: white; padding: 10px 20px; border: none; border-radius: 5px;")
        self.bouton_arreter.clicked.connect(self.arreter_surveillance)
        self.bouton_arreter.setEnabled(False)  # Désactiver le bouton au début

        # Zone du tableau de bord
        zone_tableau_bord = QVBoxLayout()
        self.label_tableau_bord = QLabel("Tableau de bord des machines")
        self.label_tableau_bord.setStyleSheet("font-size: 16px; font-weight: bold; color: #d4d4d4;")
        zone_tableau_bord.addWidget(self.label_tableau_bord)

        # Tableau des machines
        self.tableau_machines = QTableWidget()
        self.tableau_machines.setColumnCount(3)
        self.tableau_machines.setHorizontalHeaderLabels(["Adresse IP", "Services", "Vulnérabilités"])
        self.tableau_machines.verticalHeader().setVisible(False)
        zone_tableau_bord.addWidget(self.tableau_machines)

        # Zone du graphique de trafic
        zone_graphique_trafic = QVBoxLayout()
        self.label_graphique_trafic = QLabel("Graphique de trafic réseau")
        self.label_graphique_trafic.setStyleSheet("font-size: 16px; font-weight: bold; color: #d4d4d4;")
        zone_graphique_trafic.addWidget(self.label_graphique_trafic)

        self.canvas_graphique = GraphiqueTrafic() # type: ignore
        zone_graphique_trafic.addWidget(self.canvas_graphique)

        # Ajout des zones au layout principal
        layout.addLayout(zone_etat, 0, 0, 1, 2)
        layout.addLayout(zone_info_systeme, 1, 0, 1, 1)
        layout.addLayout(zone_alertes, 1, 1, 1, 1)
        layout.addLayout(zone_config, 2, 0, 1, 1)
        layout.addWidget(self.bouton_demarrer, 3, 0, 1, 1)
        layout.addWidget(self.bouton_arreter, 3, 1, 1, 1)
        layout.addLayout(zone_tableau_bord, 4, 0, 1, 1)
        layout.addLayout(zone_graphique_trafic, 4, 1, 1, 1)

        self.setLayout(layout)

        # Initialisation du thread de surveillance
        self.thread_surveillance = None
        self.regles = regles_anomalies  # Règles de détection d'anomalies par défaut
        self.machines = {}  # Dictionnaire pour stocker les informations des machines

        # Démarrer le processus de découverte automatique des machines
        self.demarrer_decouverte_auto()

        # Connecter les signaux pour mettre à jour l'interface
        self.check_apprentissage_automatique.stateChanged.connect(self.activer_apprentissage_automatique)
        self.spin_nombre_d_arbres.valueChanged.connect(self.mettre_a_jour_apprentissage_automatique)
        self.spin_contamination.valueChanged.connect(self.mettre_a_jour_apprentissage_automatique)
        self.check_protection_proactive.stateChanged.connect(self.activer_protection_proactive)
        self.check_bloquer_adresses_ip.stateChanged.connect(self.mettre_a_jour_protection_proactive)
        self.check_mettre_en_quarantaine_fichiers.stateChanged.connect(self.mettre_a_jour_protection_proactive)
        self.check_redémarrer_services.stateChanged.connect(self.mettre_a_jour_protection_proactive)

        # Afficher les informations du système
        self.afficher_info_systeme()

    def demarrer_decouverte_auto(self):
        # Vérifier si le programme est exécuté en tant que root
        if not self.est_root():
            QMessageBox.critical(self, "Erreur d'autorisation", "Le programme doit être exécuté en tant que root pour fonctionner.")
            return

        # Démarrer la découverte automatique des machines
        self.timer_decouverte = QTimer()
        self.timer_decouverte.timeout.connect(self.scanner_reseau_et_mettre_a_jour)
        self.timer_decouverte.start(10000)  # Découverte toutes les 10 secondes

    def demarrer_surveillance(self):
        # Récupérer les règles de la configuration de l'interface
        self.regles['ports_vulnerables'] = [int(port) for port in self.zone_ports.text().split(',')]
        self.regles['frequence_connexion'] = int(self.zone_frequence.text())
        self.regles['taille_paquet_suspecte'] = int(self.zone_taille_paquet.text())

        # Démarrer le thread de surveillance pour chaque machine
        for ip, services in self.machines.items():
            adresse_serveur = (ip, 80)  # Assumer que le service Web est sur le port 80
            thread_surveillance = SurveillanceServeur(adresse_serveur, self.regles, services)
            thread_surveillance.signal_alerte.connect(self.afficher_alerte)
            thread_surveillance.signal_mise_a_jour_table.connect(self.mettre_a_jour_tableau_machines)
            thread_surveillance.signal_mise_a_jour_graphique.connect(self.canvas_graphique.mettre_a_jour_graphique)
            thread_surveillance.start()

        # Mettre à jour l'état et les boutons
        self.label_etat.setText("Système en surveillance...")
        self.label_etat.setStyleSheet("font-size: 18px; font-weight: bold; color: blue;")
        self.bouton_demarrer.setEnabled(False)
        self.bouton_arreter.setEnabled(True)

    def arreter_surveillance(self):
        # Arrêter tous les threads de surveillance
        for thread in self.thread_surveillance:
            if thread:
                thread.terminate()
                thread.wait()

        # Mettre à jour l'état et les boutons
        self.label_etat.setText("Système arrêté.")
        self.label_etat.setStyleSheet("font-size: 18px; font-weight: bold; color: red;")
        self.bouton_demarrer.setEnabled(True)
        self.bouton_arreter.setEnabled(False)

    def afficher_alerte(self, message):
        self.zone_texte_alertes.append(message)

    def scanner_reseau_et_mettre_a_jour(self):
        """Scanne le réseau local et met à jour le tableau des machines."""
        # Vérifier si le programme est exécuté en tant que root
        if not self.est_root():
            QMessageBox.critical(self, "Erreur d'autorisation", "Le programme doit être exécuté en tant que root pour fonctionner.")
            return

        try:
            # Obtenir l'adresse IP de l'interface réseau
            interface = "eth0"  # Remplacer par l'interface réseau souhaitée
            adresse_ip_locale = obtenir_adresse_ip(interface)
            if not adresse_ip_locale:
                return
            # Effectuer un scan de réseau
            machines_disponibles = scanner_reseau(adresse_reseau=f"{adresse_ip_locale}/24")  # Scanner le réseau local
            self.machines = machines_disponibles
            # Mettre à jour le tableau des machines
            self.mettre_a_jour_tableau_machines()

        except Exception as e:
            logging.error(f"Erreur lors du scan de réseau: {e}")

    def mettre_a_jour_tableau_machines(self):
        """Met à jour le tableau des machines avec les informations de scan."""
        self.tableau_machines.setRowCount(len(self.machines))
        row = 0
        for ip, services in self.machines.items():
            self.tableau_machines.setItem(row, 0, QTableWidgetItem(ip))
            self.tableau_machines.setItem(row, 1, QTableWidgetItem(", ".join(services)))
            # Analyser les vulnérabilités pour la machine
            vulnerabilites = rechercher_vulnerabilites(self.machines)
            if vulnerabilites:
                self.tableau_machines.setItem(row, 2, QTableWidgetItem(", ".join(vulnerabilites)))
            row += 1

    def est_root(self):
        """Vérifie si le programme est exécuté en tant que root."""
        try:
            output = executer_commande_root("whoami")
            return "root" in output
        except Exception:
            return False

# Point d'entrée de l'application
if __name__ == '__main__':
    app = QApplication(sys.argv)
    fenetre = FenetrePrincipale()
    fenetre.show()

    sys.exit(app.exec_())
