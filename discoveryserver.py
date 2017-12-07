import sys
import json
import logging
import httplib
import requests
from flask import Flask, request, Response
from functools import wraps
from flask import abort
from ConfigParser import SafeConfigParser
import threading
from threading import Thread
import time
from datetime import datetime

from iam_proxy import OAuthToken, IAMProxy, TokenManager

DEFAULT_CLOUDLET_ENV = "production"
REGISTERED_STATUS = "registered"
DEREGISTERED_STATUS = "deregistered"
INACTIVE_STATUS = "inactive"
# Dictionary to store 'datetime' object of cloudlets on recieving heartbeat
heartbeat_dict = {}
# List to store inactive cloudlets on not recieving heartbeat
inactive_cloudlets = []

discoveryserver = Flask(__name__)

# Initialize connections with IAM
iam_proxy = None
token_manager = None


def init_IAM_connections():
    # Return immediately if IAM proxy is not plugged in
    if not IAM_PLUGGED_IN:
        return

    global iam_proxy, token_manager
    iam_proxy = IAMProxy(IAM_URL_PATTERN)

    # Register Self with IAM
    self_hosted_endpoint = SELF_HOSTED_URL_PATTERN
    target_apis = {'DS': [CLOUDLET_CATALOG_URI, APP_CATALOG_URI]}
    token = iam_proxy.register_module(MODULE_NAME,
                                      self_hosted_endpoint, target_apis, SELF_USER, SELF_PASSWORD)
    if(token.get_status() is True):
        logging.info('%s registered successfully with IAM'
                     % (MODULE_NAME))
        logging.debug('Access token received: {}'
                      .format(token.get_access_token()))
    else:
        logging.error('%s failed to register with IAM'
                      % (MODULE_NAME))
        logging.error('error: {}'
                      .format(token.get_errorjson()))

    # Start Token Management
    token_manager = TokenManager(token.get_access_token(),
                                 token.get_refresh_token(), token.get_expiry(), iam_proxy)

    token_manager.start()


class GeoIP:
    # Dictionary to map country code to continent code
    continents = {
        "AD": "EU", "AE": "AS", "AF": "AS", "AG": "NA", "AI": "NA", "AL": "EU",
        "AM": "AS", "AN": "NA", "AO": "AF", "AP": "AS", "AQ": "AN", "AR": "SA",
        "AS": "OC", "AT": "EU", "AU": "OC", "AW": "NA", "AX": "EU", "AZ": "AS",
        "BA": "EU", "BB": "NA", "BD": "AS", "BE": "EU", "BF": "AF", "BG": "EU",
        "BH": "AS", "BI": "AF", "BJ": "AF", "BL": "NA", "BM": "NA", "BN": "AS",
        "BO": "SA", "BR": "SA", "BS": "NA", "BT": "AS", "BV": "AN", "BW": "AF",
        "BY": "EU", "BZ": "NA", "CA": "NA", "CC": "AS", "CD": "AF", "CF": "AF",
        "CG": "AF", "CH": "EU", "CI": "AF", "CK": "OC", "CL": "SA", "CM": "AF",
        "CN": "AS", "CO": "SA", "CR": "NA", "CU": "NA", "CV": "AF", "CX": "AS",
        "CY": "AS", "CZ": "EU", "DE": "EU", "DJ": "AF", "DK": "EU", "DM": "NA",
        "DO": "NA", "DZ": "AF", "EC": "SA", "EE": "EU", "EG": "AF", "EH": "AF",
        "ER": "AF", "ES": "EU", "ET": "AF", "EU": "EU", "FI": "EU", "FJ": "OC",
        "FK": "SA", "FM": "OC", "FO": "EU", "FR": "EU", "FX": "EU", "GA": "AF",
        "GB": "EU", "GD": "NA", "GE": "AS", "GF": "SA", "GG": "EU", "GH": "AF",
        "GI": "EU", "GL": "NA", "GM": "AF", "GN": "AF", "GP": "NA", "GQ": "AF",
        "GR": "EU", "GS": "AN", "GT": "NA", "GU": "OC", "GW": "AF", "GY": "SA",
        "HK": "AS", "HM": "AN", "HN": "NA", "HR": "EU", "HT": "NA", "HU": "EU",
        "ID": "AS", "IE": "EU", "IL": "AS", "IM": "EU", "IN": "AS", "IO": "AS",
        "IQ": "AS", "IR": "AS", "IS": "EU", "IT": "EU", "JE": "EU", "JM": "NA",
        "JO": "AS", "JP": "AS", "KE": "AF", "KG": "AS", "KH": "AS", "KI": "OC",
        "KM": "AF", "KN": "NA", "KP": "AS", "KR": "AS", "KW": "AS", "KY": "NA",
        "KZ": "AS", "LA": "AS", "LB": "AS", "LC": "NA", "LI": "EU", "LK": "AS",
        "LR": "AF", "LS": "AF", "LT": "EU", "LU": "EU", "LV": "EU", "LY": "AF",
        "MA": "AF", "MC": "EU", "MD": "EU", "ME": "EU", "MF": "NA", "MG": "AF",
        "MH": "OC", "MK": "EU", "ML": "AF", "MM": "AS", "MN": "AS", "MO": "AS",
        "MP": "OC", "MQ": "NA", "MR": "AF", "MS": "NA", "MT": "EU", "MU": "AF",
        "MV": "AS", "MW": "AF", "MX": "NA", "MY": "AS", "MZ": "AF", "NA": "AF",
        "NC": "OC", "NE": "AF", "NF": "OC", "NG": "AF", "NI": "NA", "NL": "EU",
        "NO": "EU", "NP": "AS", "NR": "OC", "NU": "OC", "NZ": "OC", "O1": "--",
        "OM": "AS", "PA": "NA", "PE": "SA", "PF": "OC", "PG": "OC", "PH": "AS",
        "PK": "AS", "PL": "EU", "PM": "NA", "PN": "OC", "PR": "NA", "PS": "AS",
        "PT": "EU", "PW": "OC", "PY": "SA", "QA": "AS", "RE": "AF", "RO": "EU",
        "RS": "EU", "RU": "EU", "RW": "AF", "SA": "AS", "SB": "OC", "SC": "AF",
        "SD": "AF", "SE": "EU", "SG": "AS", "SH": "AF", "SI": "EU", "SJ": "EU",
        "SK": "EU", "SL": "AF", "SM": "EU", "SN": "AF", "SO": "AF", "SR": "SA",
        "ST": "AF", "SV": "NA", "SY": "AS", "SZ": "AF", "TC": "NA", "TD": "AF",
        "TF": "AN", "TG": "AF", "TH": "AS", "TJ": "AS", "TK": "OC", "TL": "AS",
        "TM": "AS", "TN": "AF", "TO": "OC", "TR": "EU", "TT": "NA", "TV": "OC",
        "TW": "AS", "TZ": "AF", "UA": "EU", "UG": "AF", "UM": "OC", "US": "NA",
        "UY": "SA", "UZ": "AS", "VA": "EU", "VC": "NA", "VE": "SA", "VG": "NA",
        "VI": "NA", "VN": "AS", "VU": "OC", "WF": "OC", "WS": "OC", "YE": "AS",
        "YT": "AF", "ZA": "AF", "ZM": "AF", "ZW": "AF"
    }

    # Dictionary to map country code to country name
    country = {
        "AF": "Afghanistan", "AX": "Aland Islands", "AL": "Albania",
        "DZ": "Algeria", "AS": "American Samoa", "AD": "Andorra",
        "AO": "Angola", "AI": "Anguilla", "AQ": "Antarctica",
        "AG": "Antigua and Barbuda", "AR": "Argentina", "AM": "Armenia",
        "AW": "Aruba", "AU": "Australia", "AT": "Austria", "AZ": "Azerbaijan",
        "BS": "Bahamas", "BH": "Bahrain", "BD": "Bangladesh", "BB": "Barbados",
        "BY": "Belarus", "BE": "Belgium", "BZ": "Belize", "BJ": "Benin",
        "BM": "Bermuda", "BT": "Bhutan", "BO": "Bolivia, Plurinational State of",
        "BQ": "Bonaire, Sint Eustatius and Saba", "BA": "Bosnia and Herzegovina",
        "BW": "Botswana", "BV": "Bouvet Island", "BR": "Brazil",
        "IO": "British Indian Ocean Territory", "BN": "Brunei Darussalam",
        "BG": "Bulgaria", "BF": "Burkina Faso", "BI": "Burundi",
        "KH": "Cambodia", "CM": "Cameroon", "CA": "Canada", "CV": "Cape Verde",
        "KY": "Cayman Islands", "CF": "Central African Republic", "TD": "Chad",
        "CL": "Chile", "CN": "China", "CX": "Christmas Island",
        "CC": "Cocos (Keeling) Islands", "CO": "Colombia", "KM": "Comoros",
        "CG": "Congo", "CD": "Congo, the Democratic Republic of the",
        "CK": "Cook Islands", "CR": "Costa Rica", "HR": "Croatia",
        "CU": "Cuba", "CW": "Curacao", "CY": "Cyprus", "CZ": "Czech Republic",
        "DK": "Denmark", "DJ": "Djibouti", "DM": "Dominica",
        "DO": "Dominican Republic", "EC": "Ecuador", "EG": "Egypt",
        "SV": "El Salvador", "GQ": "Equatorial Guinea", "ER": "Eritrea",
        "EE": "Estonia", "ET": "Ethiopia", "FK": "Falkland Islands (Malvinas)",
        "FO": "Faroe Islands", "FJ": "Fiji", "FI": "Finland", "FR": "France",
        "GF": "French Guiana", "PF": "French Polynesia",
        "TF": "French Southern Territories", "GA": "Gabon", "GM": "Gambia",
        "GE": "Georgia", "DE": "Germany", "GH": "Ghana", "GI": "Gibraltar",
        "GR": "Greece", "GL": "Greenland", "GD": "Grenada", "GP": "Guadeloupe",
        "GU": "Guam", "GT": "Guatemala", "GG": "Guernsey", "GN": "Guinea",
        "GW": "Guinea-Bissau", "GY": "Guyana", "HT": "Haiti",
        "HM": "Heard Island and McDonald Islands",
        "VA": "Holy See (Vatican City State)", "HN": "Honduras",
        "HK": "Hong Kong", "HU": "Hungary", "IS": "Iceland", "IN": "India",
        "ID": "Indonesia", "IR": "Iran, Islamic Republic of", "IQ": "Iraq",
        "IE": "Ireland", "IM": "Isle of Man", "IL": "Israel", "IT": "Italy",
        "CI": "Ivory Coast", "JM": "Jamaica", "JP": "Japan", "JE": "Jersey",
        "JO": "Jordan", "KZ": "Kazakhstan", "KE": "Kenya", "KI": "Kiribati",
        "KP": "Korea, Democratic People's Republic of",
        "KR": "Korea, Republic of", "KW": "Kuwait", "KG": "Kyrgyzstan",
        "LA": "Lao People's Democratic Republic", "LV": "Latvia",
        "LB": "Lebanon", "LS": "Lesotho", "LR": "Liberia", "LY": "Libya",
        "LI": "Liechtenstein", "LT": "Lithuania", "LU": "Luxembourg",
        "MO": "Macao", "MK": "Macedonia, the Former Yugoslav Republic of",
        "MG": "Madagascar", "MW": "Malawi", "MY": "Malaysia", "MV": "Maldives",
        "ML": "Mali", "MT": "Malta", "MH": "Marshall Islands",
        "MQ": "Martinique", "MR": "Mauritania", "MU": "Mauritius",
        "YT": "Mayotte", "MX": "Mexico",
        "FM": "Micronesia, Federated States of", "MD": "Moldova, Republic of",
        "MC": "Monaco", "MN": "Mongolia", "ME": "Montenegro", "MS": "Montserrat",
        "MA": "Morocco", "MZ": "Mozambique", "MM": "Myanmar", "NA": "Namibia",
        "NR": "Nauru", "NP": "Nepal", "NL": "Netherlands", "NC": "New Caledonia",
        "NZ": "New Zealand", "NI": "Nicaragua", "NE": "Niger", "NG": "Nigeria",
        "NU": "Niue", "NF": "Norfolk Island", "MP": "Northern Mariana Islands",
        "NO": "Norway", "OM": "Oman", "PK": "Pakistan", "PW": "Palau",
        "PS": "Palestine, State of", "PA": "Panama", "PG": "Papua New Guinea",
        "PY": "Paraguay", "PE": "Peru", "PH": "Philippines", "PN": "Pitcairn",
        "PL": "Poland", "PT": "Portugal", "PR": "Puerto Rico", "QA": "Qatar",
        "RE": " Reunion", "RO": "Romania", "RU": "Russian Federation",
        "RW": "Rwanda", "SH": "Saint Helena, Ascension and Tristan da Cunha",
        "KN": "Saint Kitts and Nevis", "LC": "Saint Lucia",
        "MF": "Saint Martin (French part)", "PM": "Saint Pierre and Miquelon",
        "VC": "Saint Vincent and the Grenadines", "BL": "Saint-Barthelemy",
        "WS": "Samoa", "SM": "San Marino", "ST": "Sao Tome and Principe",
        "SA": "Saudi Arabia", "SN": "Senegal", "RS": "Serbia",
        "SC": "Seychelles", "SL": "Sierra Leone", "SG": "Singapore",
        "SX": "Sint Maarten (Dutch part)", "SK": "Slovakia", "SI": "Slovenia",
        "SB": "Solomon Islands", "SO": "Somalia", "ZA": "South Africa",
        "GS": "South Georgia and the South Sandwich Islands",
        "SS": "South Sudan", "ES": "Spain", "LK": "Sri Lanka", "SD": "Sudan",
        "SR": "Suriname", "SJ": "Svalbard and Jan Mayen", "SZ": "Swaziland",
        "SE": "Sweden", "CH": "Switzerland", "SY": "Syrian Arab Republic",
        "TW": "Taiwan, Province of China", "TJ": "Tajikistan",
        "TZ": "Tanzania, United Republic of", "TH": "Thailand",
        "TL": "Timor-Leste", "TG": "Togo", "TK": "Tokelau", "TO": "Tonga",
        "TT": "Trinidad and Tobago", "TN": "Tunisia", "TR": "Turkey",
        "TM": "Turkmenistan", "TC": "Turks and Caicos Islands",
        "TV": "Tuvalu", "UG": "Uganda", "UA": "Ukraine",
        "AE": "United Arab Emirates", "GB": "United Kingdom",
        "US": "United States", "UM": "United States Minor Outlying Islands",
        "UY": "Uruguay", "UZ": "Uzbekistan", "VU": "Vanuatu",
        "VE": "Venezuela, Bolivarian Republic of", "VN": "Viet Nam",
        "VG": "Virgin Islands, British", "VI": "Virgin Islands, U.S.",
        "WF": "Wallis and Futuna", "EH": "Western Sahara", "YE": "Yemen",
        "ZM": "Zambia", "ZW": "Zimbabwe"
    }

    def __init__(self, ipaddr):
       # GEOIP_URL_PATTERN = "http://freegeoip.net/json/%s"%(ipaddr)
       # data = requests.get(GEOIP_URL_PATTERN).content
       # logging.debug("Client Address mapped to {}".format(data))
       # self.data = json.loads(data)
        self.country = "IN"
        self.latitude = 0.0
        self.longitude = 0.0

        if self.country in GeoIP.continents:
            self.continent = GeoIP.continents[self.country]
        else:
            self.continent = "--"

        # TODO: Ideally, this mapping should not happen.
        # Gui should save country codes in regions of cloudlets and apps
        if self.country in GeoIP.country:
            self.country = GeoIP.country[self.country]
        else:
            self.country = "--"

    def __repr__(self):
        return "country=%s, continent=%s, longitude=%f, latitude=%f" % (self.country, self.continent, self.latitude, self.longitude)


class CentralRepoHelper:

    def __init__(self):
        self.lock = threading.Lock()

    def load_cloudlet_catalog(self):
        self.cloudlet_catalog = []
        try:
            auth_header = {}
            if token_manager:
                auth_header = {'Authorization': str('Bearer ' + token_manager.get_token())}

            cloudlet_catalog_url = CLOUDLET_CATALOG_URL_PATTERN + 'cloudlets'
            db_data = requests.get(cloudlet_catalog_url, headers=auth_header)
            logging.info("Fetching cloudlets database")
            cloudlet_db = json.loads(db_data.content)

            for cloudlet in cloudlet_db:
                #Checking if mandatory fields are not None(null in cloudlet catalog)
                if (cloudlet["onBoardStatus"] is None) or (cloudlet["environment"] is None) or (cloudlet["regions"] is None) or (cloudlet["endpoints"] is None):
                    continue
                ### changing values of fields which are being used, to lowercase ###
                cloudlet["onBoardStatus"] = cloudlet["onBoardStatus"].lower()
                cloudlet["environment"] = cloudlet["environment"].lower()
                #appending only cloudlets with non-null values
                self.cloudlet_catalog.append(cloudlet)
        except KeyError, key_error:
            logging.info("KeyError(%s) while fetching cloudlets" % key_error)
            return Response(response="CLOUDLET-DISCOVERY INTERNAL_SERVER_ERROR\n", status=httplib.INTERNAL_SERVER_ERROR)
        except Exception as exception:
            logging.error("Error(%s) while fetching cloudlets from Central Repository." % exception)
            return Response(response="CLOUDLET-DISCOVERY INTERNAL_SERVER_ERROR\n", status=httplib.INTERNAL_SERVER_ERROR)

    # Function to return app@cloud url for a given application name and shortlisted cloudlet_id
    def find_vmi_app_cloud(self, cloudlet_id, app):
        """ Function to return app@cloud url for a given application name and shortlisted cloudlet_id """
        logging.info("Fetching cloudlets database for VMI apps")
        cr_helper_obj = CentralRepoHelper()
        cr_helper_obj.load_cloudlet_catalog()
        cr_cloudlets = cr_helper_obj.cloudlet_catalog
        if not cr_cloudlets:
            return Response(response="CLOUDLETS NOT FOUND\n", status=httplib.NOT_FOUND)
        response_dict = {}
        for cloudlet in cr_cloudlets:
            if cloudlet['cloudletName'] == cloudlet_id and cloudlet['onBoardStatus'] == "registered":
                logging.info("Fetching apps database")
                app_policyvmi = self.find_app(app)
                if app_policyvmi:
                    response_dict['cloud'] = {}
                    response_dict['cloudlets'] = {}
                    response_dict['cloud']['endpoints'] = {}
                    response_dict['cloud']['endpoints']['app@cloud'] = app_policyvmi["appAtCloudUrl"]
                else:
                    return Response(response="APP  NOT FOUND\n", status=httplib.NOT_FOUND)
        return json.dumps(response_dict)

    def find_app(self, app):
        # Fetching app data from Central Repository
        app_data = None
        try:
            app_catalog_url = APP_CATALOG_URL_PATTERN + "application" + "/" + app
            response_app_catalog = requests.get(app_catalog_url)
            if response_app_catalog.status_code != httplib.OK:
                raise Exception("Unable to fetch app %s. Check the app name." % app)
            app_data = json.loads(response_app_catalog.content)

            ### Changing value of "enable" key to str, if boolean  ###
            if type(app_data["enable"]) is bool:
                app_data["enable"] = str(app_data["enable"])
        except Exception as exception:
            logging.error(exception)
        return app_data

############  Cloudlet Capacity Code #####################################
    """
    def calculate_capacity(self, cloudlets, cloudlets_capacity, cloudlet_usage, app_requirement):
        shortlist = []
        # for item in cloudlets_capacity:
        for item in cloudlets:

            memory = re.findall(
                '\d+', str(cloudlets_capacity[item]['memory']))

            storage = re.findall(
                '\d+', str(cloudlets_capacity[item]['storage']))

            cpu = re.findall(
                '\d+', str(cloudlets_capacity[item]['cpu']))

            memory_capacity = int(memory[0])
            storage_capacity = int(storage[0])
            cpu_capacity = int(cpu[0])

            mem_used = re.findall(
                '\d+', str(cloudlet_usage[item]['memory']))

            storage_used = re.findall(
                '\d+', str(cloudlet_usage[item]['storage']))

            cpu_used = re.findall(
                '\d+', str(cloudlet_usage[item]['cpu']))

            memory_in_use = int(mem_used[0])
            storage_in_use = int(storage_used[0])
            cpu_in_use = int(cpu_used[0])

            available_memory = memory_capacity - \
                (memory_in_use / 100.0) * memory_capacity
            available_storage = storage_capacity - \
                (storage_in_use / 100.0) * storage_capacity
            available_cpu = cpu_capacity - \
                (cpu_in_use / 100.0) * cpu_capacity

            app_req_memory = re.findall(
                '\d+', str(app_requirement['memory']))

            app_req_cpu = re.findall(
                '\d+', str(app_requirement['cpu']))

            app_req_storage = re.findall(
                '\d+', str(app_requirement['storage']))

            if available_memory > int(app_req_memory[0]) and \
                    available_cpu > int(app_req_cpu[0]) and \
                    available_storage > int(app_req_storage[0]):
                shortlist.append(item)
        return shortlist
    """

    def cloudlets(self, app, country=None, continent=None, environment=DEFAULT_CLOUDLET_ENV, isvmireqd=None):
        app_policy = self.find_app(app)
        response_dict = {}
        if app_policy:
            if app_policy["enable"] != "True":
                return {}
            if country and app_policy["regions"] and country not in app_policy["regions"] and continent not in app_policy["regions"]:
                return {}

            # Search for VMI enabled cloudlets if app has requested for it
            if isvmireqd:
                print "VMI reqd is true"
                if app_policy["lowLatency"] == "Y":
                    if country:
                        # Choose from low-latency clouds for specific region
                        filter_cloudlet = lambda v: (country in v["regions"][
                            "lowLatency"] or continent in v["regions"]["lowLatency"]) and (v["onBoardStatus"] == REGISTERED_STATUS) and (v["environment"] == environment) and (v["vmiEnabled"] == "Y")
                    else:
                        # Choose from all low-latency clouds
                        filter_cloudlet = lambda v: (v["regions"]["lowLatency"]) and (
                            v["onBoardStatus"] == REGISTERED_STATUS) and (v["environment"] == environment) and (v["vmiEnabled"] == "Y")
                else:
                    if country:
                        # Choose from all clouds for specific region
                        filter_cloudlet = lambda v: (country in v["regions"][
                            "all"] or continent in v["regions"]["all"]) and (v["onBoardStatus"] == REGISTERED_STATUS) and (v["environment"] == environment) and (v["vmiEnabled"] == "Y")
                    else:
                        # Choose from all clouds

                        filter_cloudlet = lambda v: (v["regions"]["all"]) and (
                            v["onBoardStatus"] == REGISTERED_STATUS) and (v["environment"] == environment) and (v["vmiEnabled"] == "Y")

            #Search for all cloudlets if isvmireqd flag is false
            else:
                print "VMI reqd is false"
                if app_policy["lowLatency"] == "Y":
                    if country:
                        # Choose from low-latency clouds for specific region
                        filter_cloudlet = lambda v: (country in v["regions"][
                            "lowLatency"] or continent in v["regions"]["lowLatency"]) and (v["onBoardStatus"] == REGISTERED_STATUS) and (v["environment"] == environment)
                    else:
                        # Choose from all low-latency clouds
                        filter_cloudlet = lambda v: (v["regions"]["lowLatency"]) and (
                            v["onBoardStatus"] == REGISTERED_STATUS) and (v["environment"] == environment)
                else:
                    if country:
                        # Choose from all clouds for specific region
                        filter_cloudlet = lambda v: (country in v["regions"][
                            "all"] or continent in v["regions"]["all"]) and (v["onBoardStatus"] == REGISTERED_STATUS) and (v["environment"] == environment)
                    else:
                        # Choose from all clouds

                        filter_cloudlet = lambda v: (v["regions"]["all"]) and (
                            v["onBoardStatus"] == REGISTERED_STATUS) and (v["environment"] == environment)

            self.load_cloudlet_catalog()
            cloudlets = [v['cloudletName']
                            for v in self.cloudlet_catalog if filter_cloudlet(v)]

            """
            # Code for shortlisting of code by usage and capacity of cloud

             capacity_url = "http://%s:%d/api/v1.0/centralrepo/cloudletcatalog/capacity?cloudlet_ids=%s" % (
                 MEC_CLOUDLET_CATALOG_IP, MEC_CLOUDLET_CATALOG_PORT, cloudlets)
             cloudlets_capacity = json.loads(requests.get(capacity_url).content)

             usage_url = "http://%s:%d/api/v1.0/centralrepo/cloudletcatalog/usage?cloudlet_ids=%s" % (
                 MEC_CLOUDLET_CATALOG_IP, MEC_CLOUDLET_CATALOG_PORT, cloudlets)
             cloudlet_usage = json.loads(requests.get(usage_url).content)

             app_resource_url = "http://%s:%d/api/v1.0/centralrepo/appcatalog/resource/%s" % (
                 MEC_APP_CATALOG_IP, MEC_APP_CATALOG_PORT, app)
             app_requirement = json.loads(
                 requests.get(app_resource_url).content)
             shortlist = self.calculate_capacity(
                 cloudlets, cloudlets_capacity, cloudlet_usage, app_requirement)
             if shortlist:
                 response_dict['cloudlets'] = {}
                 for cloudlet_id in shortlist:
                     response_dict['cloudlets'][cloudlet_id] = {}
                     response_dict['cloudlets'][cloudlet_id]['endpoints'] = {}
                     if self.cloudlet_catalog["cloudlets"][cloudlet_id]["endpoints"]["probe"]:
                         response_dict['cloudlets'][cloudlet_id]['endpoints']['probe'] = self.cloudlet_catalog["cloudlets"][cloudlet_id]["endpoints"]["probe"][
                             "protocol"] + "://" + self.cloudlet_catalog["cloudlets"][cloudlet_id]["endpoints"]["probe"]["ip"] + ":" +
                                 self.cloudlet_catalog["cloudlets"][cloudlet_id]["endpoints"]["probe"]["port"]
                 return json.dumps(response_dict)
            """
            if len(cloudlets) != 0:
                response_dict['cloud'] = {}
                response_dict['cloudlets'] = {}
                response_dict['cloud']['endpoints'] = {}
                response_dict['cloud']['endpoints']['app@cloud'] = app_policy["appAtCloudUrl"]
                for cloudlet_id in cloudlets:
                    response_dict['cloudlets'][cloudlet_id] = {}
                    response_dict['cloudlets'][cloudlet_id]['endpoints'] = {}

                    for cloudlet_dict in self.cloudlet_catalog:
                        if cloudlet_id == cloudlet_dict["cloudletName"]:
                            for endpoint_dict in cloudlet_dict["endpoints"]:
                                if endpoint_dict["name"] == 'probe':
                                    response_dict['cloudlets'][cloudlet_id]['endpoints']['probe'] = "%s://%s:%s" % (endpoint_dict['protocol'], endpoint_dict['ip'], endpoint_dict['port'])
        return response_dict


class EventSubscribers:

    def __init__(self, subscribers_file):
        self.file = subscribers_file
        self.parser = SafeConfigParser()
        self.parser.read(subscribers_file)
        self.event_list = self.parser.sections()

    def notify(self, data_for_subscriber, event):
        for subscriber, subscriber_url in self.parser.items(event):
            try:
                response_subscriber = requests.post(
                    subscriber_url, params=data_for_subscriber)
                logging.debug("Notify:Response from subscriber %s is [%s]\nsubscriber url:%s" % (
                    subscriber, str(response_subscriber.status_code), subscriber_url))
            except Exception as exception:
                logging.debug("Notify:url %s not accessible for %s\nerror:%s" % (
                    subscriber_url, subscriber, exception))

    def subscribe(self, subscriber_name, subscriber_url, event_list):
        response_message = ""
        for event in event_list:
            if event not in self.event_list:
                self.parser.add_section(event)

            if self.parser.has_option(event, subscriber_name):
                response_message += "[%s:ALREADY_SUBSCRIBED_FOR_EVENT %s]" % (
                    subscriber_name, event)

            else:
                self.parser.set(event, subscriber_name, subscriber_url)
                with open(self.file, "w") as cfgfile:
                    self.parser.write(cfgfile)
                self.parser.read(self.file)
                self.event_list = self.parser.sections()
                response_message += "[%s:SUBSCRIBE_SUCCESSFULL_FOR_EVENT %s]" % (
                    subscriber_name, event)

        return Response(response=response_message + "\n", status=httplib.OK)

    def unsubscribe(self, subscriber_name, event_list):
        response_message = ""
        for event in event_list:
            if event not in self.event_list:
                response_message += "[%s:EVENT_DOES_NOT_EXIST]" % event
            if self.parser.has_option(event, subscriber_name):
                self.parser.remove_option(event, subscriber_name)
                with open(self.file, "w") as cfgfile:
                    self.parser.write(cfgfile)
                self.parser.read(self.file)
                self.event_list = self.parser.sections()
                response_message += "[%s:UNSUBSCRIBE_SUCCESSFULL_FOR_EVENT %s]" % (
                    subscriber_name, event)
            else:
                response_message += "[%s:NOT_SUBSCRIBED_FOR_EVENT %s]" % (
                    subscriber_name, event)

        return Response(response=response_message + "\n", status=httplib.OK)


class Heartbeat(threading.Thread):

    def __init__(self, delay):
        threading.Thread.__init__(self)
        self.delay = delay
        self.init_heartbeat_dict_inactive_cloudlets()

    def init_heartbeat_dict_inactive_cloudlets(self):
        """
        Function to initialize heartbeat_dict and inactive_cloudlets when DS starts first time
        """
        global heartbeat_dict
        global inactive_cloudlets
        default_heartbeat_time = datetime.now()
        cr_helper_obj = CentralRepoHelper()
        cr_helper_obj.load_cloudlet_catalog()
        cr_cloudlets = cr_helper_obj.cloudlet_catalog
        if cr_cloudlets:
            for cloudlet in cr_cloudlets:
                if cloudlet["onBoardStatus"] == REGISTERED_STATUS:
                    heartbeat_dict[cloudlet["cloudletName"]] = default_heartbeat_time
                if cloudlet["onBoardStatus"] == INACTIVE_STATUS:
                    inactive_cloudlets.append(cloudlet["cloudletName"])
        else:
            logging.error(
                "No data recieved from Central repository to initialize heartbeats. Check if Central repository is UP.")
        del cr_helper_obj

    def run(self):
        self.check_heartbeat()

    def check_heartbeat(self):
        global heartbeat_dict
        global inactive_cloudlets
        delay = self.delay
        auth_header = {}
        auth_header["Content-type"] = "application/json"
        if token_manager:
            auth_header['Authorization'] = str('Bearer ' + token_manager.get_token())
        while(True):
            time.sleep(delay)
            # making copy of heartbeat_dict because heartbeat_dict may be
            # updated during iteration
            heartbeat_dict_local = heartbeat_dict
            if heartbeat_dict_local:
                for cloudlet in heartbeat_dict_local:
                    time_since_last_heartbeat = (
                        datetime.now() - heartbeat_dict_local[cloudlet]).seconds
                    if (time_since_last_heartbeat >
                            INTERVAL_TO_DEACTIVATE_CLOUDLET) and (cloudlet not in inactive_cloudlets):
                        url_cloudlet_update = CLOUDLET_CATALOG_URL_PATTERN + "cloudlet" + "/" + cloudlet + "/"
                        try:
                            data_for_subscriber = {'cloudlet': cloudlet, 'onBoardStatus': INACTIVE_STATUS}
                            # fetching cloudlet data
                            response = requests.get(url_cloudlet_update, headers=auth_header)
                            # changing "onBoardstatus" to INACTIVE_STATUS
                            inactive_cloudlet_dict = json.loads(response.content)
                            inactive_cloudlet_dict["onBoardStatus"] = INACTIVE_STATUS
                            # Updating Central Repository
                            logging.debug("Deactivating cloudlet [%s]" % cloudlet)
                            cloudlet_catalog_response = requests.put(
                                url_cloudlet_update, data=json.dumps(inactive_cloudlet_dict), headers=auth_header)
                            #raise exception if change status not successful
                            if (cloudlet_catalog_response.status_code != httplib.OK):
                                logging.debug("Error in deactivating cloudlet [%s], response from Cloudlet Catalog [%s:%s]"
                                        % (cloudlet, cloudlet_catalog_response.status_code, cloudlet_catalog_response.content))
                                raise Exception("Failed to reach URL [%s]" % url_cloudlet_update)
                            inactive_cloudlets.append(cloudlet)
                            #subscribers.notify(data_for_subscriber, "heartbeat")
                            # Notifying in a new thread
                            thread_notify = Thread(target=subscribers.notify, args=(data_for_subscriber, "heartbeat"))
                            thread_notify.start()
                            logging.info(
                                "!!! cloudlet [%s] changed onBoardStatus, registered to inactive !!!" % cloudlet)
                        except Exception as exception:
                            logging.error(
                                "ERROR in deactivating the cloudlet [%s]" % cloudlet)
                            logging.debug(exception)
                    if (time_since_last_heartbeat <= INTERVAL_TO_DEACTIVATE_CLOUDLET) and (cloudlet in inactive_cloudlets):
                        inactive_cloudlets.remove(cloudlet)
                        logging.info(
                            "*** cloudlet [%s] onBoardStatus changed, inactive to registered ***" % cloudlet)

# Method introduced to fetch app@cloud for a specific app and cloudlet_id
@discoveryserver.route("/api/v1.0/discover/<developer_id>/<app_id>/<cloudlet_id>", methods=['GET'])
def discover_vmicloudlets(*args, **kwargs):
    logging.info("Fetching app@cloud for VMI applications")
    developer_id = kwargs['developer_id']
    app_id = kwargs['app_id']
    cloudlet_id = kwargs['cloudlet_id']
    #app = "%s.%s" % (developer_id, app_id)
    cr_helper = CentralRepoHelper()
    return cr_helper.find_vmi_app_cloud(cloudlet_id, app_id)

@discoveryserver.route("/api/v1.0/discover/<developer_id>/<app_id>", methods=['GET'])
def discover_cloudlets(*args, **kwargs):
    #Shortlists a cloudlet
    try:
        environment = request.args.get('environment').lower()
    except:
        environment = DEFAULT_CLOUDLET_ENV

    # client_ip will come in header of request.
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)

    if client_ip:
        split_str = client_ip.split('.')

        if len(split_str) != 4:
            return Response(response="Invalid Client IP\n", status=httplib.BAD_REQUEST)
        elif len(split_str) == 4:
            for item in split_str:
                if int(item) > 255 or int(item) < 0:
                    return Response(response="Invalid Client IP\n", status=httplib.BAD_REQUEST)

            # Find the country/continent of the client
            logging.debug("Find location for client %s" % client_ip)
            match = GeoIP(client_ip)
            logging.debug(repr(match))
    else:
        match = None

    # Get the candidate cloudlets for the app (if the app is not enabled this
    # will return an empty list)
    app_id = kwargs['app_id']
    # Fetch isVMIReqd from url to determine if VMI enabled cloudlets are to be shortlisted
    isvmireqd = request.args.get('isVMIReqd')

    cr_helper = CentralRepoHelper()
    cloudlets = cr_helper.cloudlets(
        app_id, match.country, match.continent, environment, isvmireqd) if match else cr_helper.cloudlets(app_id, isvmireqd)

    if len(cloudlets) > 0:
        return json.dumps(cloudlets)
    else:
        return Response(response="CLOUDLETS NOT FOUND\n", status=httplib.NOT_FOUND)


@discoveryserver.route("/api/v1.0/discover/<cloudlet_id>/register", methods=['PUT'])
def register_cloudlet(cloudlet_id):
    """
    Registers a cloudlet
    """
    try:
        data_for_subscriber = {
            'cloudlet': cloudlet_id,
            'status': REGISTERED_STATUS
        }
        url_cloudlet_catalog = CLOUDLET_CATALOG_URL_PATTERN + "cloudlet" + "/" + cloudlet_id + "/"
        headers = {}
        headers["Content-type"] = "application/json"
        if token_manager:
            headers['Authorization'] = str('Bearer ' + token_manager.get_token())
        # fetching cloudlet data
        response = requests.get(url_cloudlet_catalog, headers=headers)
        updated_data = json.loads(response.content)
        updated_data["onBoardStatus"] = REGISTERED_STATUS
        response = requests.put(
            url_cloudlet_catalog, data=json.dumps(updated_data), headers=headers)

        if response.status_code == httplib.OK:
            # Notifying in a new thread
            thread_notify = Thread(target=subscribers.notify, args=(data_for_subscriber, "register"))
            thread_notify.start()
            resp = Response(
                response="CLOUDLET-REGISTER [%s] SUCCESS\n" % cloudlet_id)
        else:
            resp = Response(
                response="CLOUDLET-REGISTER [%s] NOT FOUND\n" % cloudlet_id, status=httplib.NOT_FOUND)

    except Exception as exception:
        logging.error("Error occured while registering cloudlet %s\nerror:%s" % (cloudlet_id, exception))
        resp = Response(
            response="CLOUDLET-REGISTER INTERNAL_SERVER_ERROR\n", status=httplib.INTERNAL_SERVER_ERROR)
    return resp


@discoveryserver.route("/api/v1.0/discover/<cloudlet_id>/deregister", methods=['PUT'])
def deregister_cloudlet(cloudlet_id):
    """
    Deregisters a cloudlet
    """
    try:
        data_for_subscriber = {
            'cloudlet': cloudlet_id,
            'status': DEREGISTERED_STATUS
        }
        headers = {}
        headers["Content-type"] = "application/json"
        if token_manager:
            headers['Authorization'] = str('Bearer ' + token_manager.get_token())
        url_cloudlet_catalog = CLOUDLET_CATALOG_URL_PATTERN + "cloudlet" + "/" + cloudlet_id + "/"
        # fetching cloudlet data
        response = requests.get(
            url_cloudlet_catalog, headers=headers)
        updated_data = json.loads(response.content)
        updated_data["onBoardStatus"] = DEREGISTERED_STATUS
        response = requests.put(
            url_cloudlet_catalog, data=json.dumps(updated_data), headers=headers)
        if response.status_code == httplib.OK:
            # Notifying in a new thread
            thread_notify = Thread(target=subscribers.notify, args=(data_for_subscriber, "register"))
            thread_notify.start()
            resp = Response(
                response="CLOUDLET-DEREGISTER [%s] SUCCESS\n" % cloudlet_id)
        else:
            resp = Response(
                response="CLOUDLET-DEREGISTER [%s] NOT FOUND\n" % cloudlet_id, status=httplib.NOT_FOUND)
    except Exception as exception:
        logging.error("Error occured while deregistering cloudlet %s\nerror:%s" % (cloudlet_id, exception))
        resp = Response(
            response="CLOUDLET-DEREGISTER INTERNAL_SERVER_ERROR\n", status=httplib.INTERNAL_SERVER_ERROR)
    return resp


@discoveryserver.route("/api/v1.0/discover/subscribe", methods=['POST'])
def subscribe():
    """
    Subscribes a intreseted party for a given event(example register, deregister, heartbeat)
    """
    try:
        subscribing_party = request.json.get('subscriber')
        subscribing_party_url = request.json.get('url')
        subscribing_party_event = request.json.get('event')

        resp = subscribers.subscribe(
            subscribing_party, subscribing_party_url, subscribing_party_event)

    except Exception as exception:
        logging.error("Error occured while subscribing %s for %s\nerror:%s" % (subscribing_party, subscribing_party_event, exception))
        resp = Response(
            response="SUBSCRIBE_INTERNAL_SERVER_ERROR\n", status=httplib.INTERNAL_SERVER_ERROR)
    return resp


@discoveryserver.route("/api/v1.0/discover/unsubscribe", methods=['POST'])
def unsubscribe():
    """
    Unsubscribes a intreseted party for a given event(example register, deregister, heartbeat)
    """
    try:
        subscribing_party = request.json.get('subscriber')
        subscribing_party_event = request.json.get('event')

        resp = subscribers.unsubscribe(
            subscribing_party, subscribing_party_event)
    except Exception as exception:
        logging.error("Error occured while unsubscribing %s for %s\nerror:%s" % (subscribing_party, subscribing_party_event, exception))
        resp = Response(
            response="UNSUBSCRIBE_INTERNAL_SERVER_ERROR\n", status=httplib.INTERNAL_SERVER_ERROR)
    return resp


@discoveryserver.route('/api/v1.0/discover/heartbeat', methods=['PUT'])
def update_heartbeat_dict():
    """
    keep tracks of heartbeat of each cloudlet
    """
    lock = threading.Lock()
    heartbeat_recieve_time = datetime.now()
    clc_id = request.args.get('heartbeat_source')
    lock.acquire()
    heartbeat_dict[clc_id] = heartbeat_recieve_time
    lock.release()
    return Response(status=httplib.OK)

#################### END: API Definition ####################

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)-15s %(levelname)-8s %(filename)-16s %(lineno)4d %(message)s')


if __name__ == '__main__':

    if len(sys.argv) < 6:
        print("Usage: %s <self_fqdn> <app_catalog_ip> <cloudlet_catalog_ip> <iam_ip> <configfile_location>"
              % (sys.argv[0]))
        sys.exit(1)
    SELF_IP = sys.argv[1]
    MEC_APP_CATALOG_IP = sys.argv[2]
    MEC_CLOUDLET_CATALOG_IP = sys.argv[3]
    MEC_IAM_IP = sys.argv[4]
    MEC_CONF_FILE = sys.argv[5]

    # Reading the "discoveryserver.config" file
    section_name = 'discoveryserver'
    config_parser = SafeConfigParser()
    config_parser.read(MEC_CONF_FILE)
    INTERVAL_TO_CHECK_HEARTBEAT = int(config_parser.get(section_name,
                                                        'INTERVAL_TO_CHECK_HEARTBEAT'))
    INTERVAL_TO_DEACTIVATE_CLOUDLET = int(config_parser.get(
        section_name, 'INTERVAL_TO_DEACTIVATE_CLOUDLET'))
    SUBSCRIBER_FILE = config_parser.get(section_name,
                                        'SUBSCRIBER_FILE')
    subscribers = EventSubscribers(SUBSCRIBER_FILE)

    # Module details
    MODULE_NAME = str(config_parser.get(section_name, 'MODULE_NAME'))

    # Initialize Port numbers
    MEC_APP_CATALOG_PORT = int(
        config_parser.get(section_name, 'MEC_APP_CATALOG_PORT'), 16)
    MEC_CLOUDLET_CATALOG_PORT = int(
        config_parser.get(section_name, 'MEC_CLOUDLET_CATALOG_PORT'), 16)
    MEC_IAM_PORT = int(config_parser.get(section_name, 'MEC_IAM_PORT'), 16)
    MEC_DISCOVERY_SERVER_PORT = int(
        config_parser.get(section_name, 'MEC_DISCOVERY_SERVER_PORT'), 16)

    # Initialize URL patterns
    CLOUDLET_CATALOG_URI = str(
        config_parser.get(section_name, 'CLOUDLET_CATALOG_URI'))
    CLOUDLET_CATALOG_URL_PATTERN = "http://%s:%d%s" % (
        MEC_CLOUDLET_CATALOG_IP, MEC_CLOUDLET_CATALOG_PORT, CLOUDLET_CATALOG_URI)
    APP_CATALOG_URI = str(config_parser.get(section_name, 'APP_CATALOG_URI'))

    APP_CATALOG_URL_PATTERN = "http://%s:%d%s" % (
        MEC_APP_CATALOG_IP, MEC_APP_CATALOG_PORT, APP_CATALOG_URI)
    IAM_URL_PATTERN = "http://%s:%d" % (MEC_IAM_IP, MEC_IAM_PORT)
    SELF_HOSTED_AT = str(config_parser.get(section_name, 'SELF_HOSTED_AT'))
    SELF_HOSTED_URL_PATTERN = "http://%s:%d%s" % (
        SELF_IP, MEC_DISCOVERY_SERVER_PORT, SELF_HOSTED_AT)

    # Initialize IAM User
    SELF_USER = str(config_parser.get(section_name, 'SELF_USER'))
    SELF_PASSWORD = str(config_parser.get(section_name, 'SELF_PASSWORD'))

    # Check if IAM plugin in enabled
    if(int(config_parser.get(section_name, 'IAM_PLUGGED_IN')) == 1):
        IAM_PLUGGED_IN = True
        init_IAM_connections()
    else:
        IAM_PLUGGED_IN = False

    # Starting thread for heartbeat check
    #heartbeat_t = Heartbeat(INTERVAL_TO_CHECK_HEARTBEAT)
    #heartbeat_t.setDaemon(True)
    #heartbeat_t.start()
    logging.basicConfig(filename='/opt/logs/discovery.log', level=logging.DEBUG,
                    format='%(asctime)-15s %(levelname)-8s %(filename)-16s %(lineno)4d %(message)s')

    discoveryserver.run(
        host=SELF_IP, port=MEC_DISCOVERY_SERVER_PORT, threaded=True)
