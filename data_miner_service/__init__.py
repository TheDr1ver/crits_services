import re
import logging

from crits.services.core import Service, ServiceConfigError
from crits.emails.email import Email
from crits.events.event import Event
from crits.raw_data.raw_data import RawData
from crits.samples.sample import Sample
from crits.domains.domain import TLD
from crits.indicators.indicator import Indicator
from crits.core.data_tools import make_ascii_strings
from crits.vocabulary.indicators import IndicatorTypes

logger = logging.getLogger(__name__)


class DataMinerService(Service):
    """
    Mine data for useful information

    Currently this service only runs on RawData and Samples. This could be
    expanded to work on email bodies + headers or other top-level objects which
    contain a chunk of data ripe for parsing potential indicators.
    """

    name = "DataMiner"
    version = '1.0.0'
    template = "data_miner_service_template.html"
    supported_types = ['Event', 'RawData', 'Sample', 'Email']
    description = "Mine a chunk of data for useful information."

    @staticmethod
    def valid_for(obj):
        if isinstance(obj, Sample):
            if obj.filedata.grid_id == None:
                raise ServiceConfigError("Missing filedata.")

    def run(self, obj, config):
        if isinstance(obj, Event):
            data = obj.description
        elif isinstance(obj, RawData):
            data = obj.data
        elif isinstance(obj, Email):
            data = obj.raw_body
        elif isinstance(obj, Sample):
            samp_data = obj.filedata.read()
            data = make_ascii_strings(data=samp_data)
            if not data:
                self._debug("Could not find sample data to parse.")
                return
        else:
            self._debug("This type is not supported by this service.")
            return

        ips = extract_ips(data)
        for ip in ips:
            tdict = {'Type': IndicatorTypes.IPV4_ADDRESS}
            id_ = Indicator.objects(value=ip).only('id').first()
            if id_:
                tdict['exists'] = str(id_.id)
            self._add_result('Potential IP Address', ip, tdict)
        domains = extract_domains(data)
        for domain in domains:
            tdict = {'Type': IndicatorTypes.DOMAIN}
            id_ =  Indicator.objects(value=domain).only('id').first()
            if id_:
                tdict['exists'] = str(id_.id)
            self._add_result('Potential Domains', domain, tdict)
        uris = extract_uris(data)
        for uri in uris:
            tdict = {'Type': IndicatorTypes.URI}
            id_ = Indicator.objects(value=uri).only('id').first()
            if id_:
                tdict['exists'] = str(id_.id)
            self._add_result('Potential URIs', uri, tdict)
        emails = extract_emails(data)
        for email in emails:
            tdict = {'Type': IndicatorTypes.EMAIL_ADDRESS}
            id_ = Indicator.objects(value=email).only('id').first()
            if id_:
                tdict['exists'] = str(id_.id)
            self._add_result('Potential Emails', email, tdict)
        hashes = extract_hashes(data)
        for hash_ in hashes:
            type_ = hash_[0]
            val = hash_[1]
            tdict = {'Type': type_}
            if type_ == IndicatorTypes.MD5:
                id_ = Sample.objects(md5=val).only('id').first()
            elif type_ == IndicatorTypes.SHA1:
                id_ = Sample.objects(sha1=val).only('id').first()
            elif type_ == IndicatorTypes.SHA256:
                id_ = Sample.objects(sha256=val).only('id').first()
            elif type_ == IndicatorTypes.SSDEEP:
                id_ = Sample.objects(ssdeep=val).only('id').first()
            else:
                id_ = None
            if id_:
                tdict['exists'] = str(id_.id)
            self._add_result('Potential Samples', val, tdict)

# hack of a parser to extract potential ip addresses from data
def extract_ips(data):
    pattern = r"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)([ (\[]?(\.|dot)[ )\]]?(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3})"
    ips = [each[0] for each in re.findall(pattern, data)]
    for item in ips:
        location = ips.index(item)
        ip = re.sub("[ ()\[\]]", "", item)
        ip = re.sub("dot", ".", ip)
        ips.remove(item)
        ips.insert(location, ip)
    return ips

# hack of a parser to extract potential domains from data
def extract_domains(data):
    pattern = r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?[\.[a-zA-Z]{2,}'
    domains = [each for each in re.findall(pattern, data) if len(each) > 0]
    final_domains = []
    for item in domains:
        if len(item) > 1 and item.find('.') != -1:
            try:
                tld = item.split(".")[-1]
                check = TLD.objects(tld=tld).first()
                if check:
                    final_domains.append(item)
            except:
                pass
    return final_domains

# hack of a parser to extract potential URIs from data
def extract_uris(data):
    pattern = r'(http|ftp|https)://([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?'
    results = re.findall(pattern,data)
    #domains = [each[1] for each in results if len(each) > 0]
    uris = [each[2] for each in results if len(each) > 0]
    final_uris = []
    for item in uris:
        final_uris.append(item)
    return final_uris

# hack of a parser to extract potential emails from data
def extract_emails(data):
    pattern = r'[a-zA-Z0-9-\.\+]+@.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?[\.[a-zA-Z]{2,}'
    emails = [each for each in re.findall(pattern, data) if len(each) > 0]
    final_emails = []
    for item in emails:
        if len(item) > 1 and item.find('.') != -1:
            try:
                tld = item.split(".")[-1]
                check = TLD.objects(tld=tld).first()
                if check:
                    final_emails.append(item)
            except:
                pass
    return final_emails

# hack of a parser to extract potential domains from data
def extract_hashes(data):

    re_md5 = re.compile("\\b[a-f0-9]{32}\\b", re.I | re.S | re.M)
    re_sha1 = re.compile("\\b[a-f0-9]{40}\\b", re.I | re.S | re.M)
    re_sha256 = re.compile("\\b[a-f0-9]{64}\\b", re.I | re.S | re.M)
    re_ssdeep = re.compile("\\b\\d{2}:[A-Za-z0-9/+]{3,}:[A-Za-z0-9/+]{3,}\\b", re.I | re.S | re.M)

    final_hashes = []
    md5 = IndicatorTypes.MD5
    sha1 = IndicatorTypes.SHA1
    sha256 = IndicatorTypes.SHA256
    ssdeep = IndicatorTypes.SSDEEP
    final_hashes.extend(
        [(md5,each) for each in re.findall(re_md5, data) if len(each) > 0]
    )
    final_hashes.extend(
        [(sha1,each) for each in re.findall(re_sha1, data) if len(each) > 0]
    )
    final_hashes.extend(
        [(sha256,each) for each in re.findall(re_sha256, data) if len(each) > 0]
    )
    final_hashes.extend(
        [(ssdeep,each) for each in re.findall(re_ssdeep, data) if len(each) > 0]
    )
    return final_hashes

