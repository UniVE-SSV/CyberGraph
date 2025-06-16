import requests
import math
import os
from mitreattack.stix20 import MitreAttackData
from dotenv import load_dotenv
from neo4j import GraphDatabase
import time
import csv
import re
import json
import sys


class CyberGraph:

    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        self.db="neo4j"

    def close(self):
        self.driver.close()

    # ==============================================
    # ============ INTERNAL UTILITIES ==============
    # ==============================================

    def printProgressBar(self, value, max, label):
        n_bar = 40 # Size of progress bar
        sup= value/max
        sys.stdout.write('\r')
        bar = '█' * int(n_bar * sup)
        bar = bar + '-' * int(n_bar * (1-sup))

        sys.stdout.write(f"{label.ljust(10)} | [{bar:{n_bar}s}] {int(100 * sup)}% ")
        sys.stdout.flush()

    # ==============================================
    # ===== COMMON VARIABLES (Of: CWE, CAPEC) ======
    # ==============================================

    relationship = {
        "ChildOf": {                    # (current)<--(related_cwe)
            "relationship":"PARENT_OF",
            "direction":"Left"
        },           
        "CanPrecede":{                  # (current)-->(related_cwe)
            "relationship":"CAN_PRECEDE",
            "direction":"Right"
        },
        "CanFollow":{                    # (current)<--(related_cwe)
            "relationship":"CAN_PRECEDE",
            "direction":"Left"
        },
        "PeerOf":{                      # (current)--(related_cwe)  --> as default
            "relationship":"PEER_OF",  
            "direction":"Right"
        }, 
        "CanAlsoBe":{                   # (current)--(related_cwe)  --> as default
            "relationship":"CAN_ALSO_BE",
            "direction":"Right"
        },
        "Requires":{                    # (current)-->(related_cwe)
            "relationship":"REQUIRES",
            "direction":"Right"
        }
    }

    # ==============================================
    # =============== HANDLE CNA ===================
    # ==============================================

    @staticmethod
    def _create_cna(tx, elements):
        tx.run("MERGE (cna:CNA { name:$name, link:$link }) SET cna:"+ elements["label"], 
            name=elements["name"],
            link=elements["link"])

    @staticmethod
    def _create_disclosure_policy(tx, elements):
        tx.run("""
            MATCH (cna:CNA { name:$cnaName })
            MERGE (dp:DisclosurePolicy { link:$link, description:$description })
            MERGE (cna)-[:HAS_DISCLOSURE_POLICY]->(dp)
            """, 
            link=elements["link"],
            description=elements["description"],
            cnaName=elements["cnaName"])

    @staticmethod
    def _create_organization_type(tx, elements):
        tx.run("""
            MATCH (cna:CNA { name:$cnaName })
            MERGE (ot:OrganizationType { type:$type })
            MERGE (cna)-[:WORKS_IN_THE_FIELD_OF]->(ot)
            """, 
            type=elements["type"],
            cnaName=elements["cnaName"])

    @staticmethod
    def _create_security_advisory(tx, elements):
        tx.run("""
            MATCH (cna:CNA { name:$cnaName })
            MERGE (sa:SecurityAdvisory { link:$link, description:$description })
            MERGE (cna)-[:HAS_SECURITY_ADVISORY]->(sa)
            """, 
            link=elements["link"],
            description=elements["description"],
            cnaName=elements["cnaName"])

    @staticmethod
    def _create_contact_info(tx, elements):
        tx.run("""
            MATCH (cna:CNA { name:$cnaName })
            MERGE (contact:ContactInfo:"""+ elements["additionalLabel"] +""" { contact:$contact, description:$description })
            MERGE (cna)-[:"""+ elements["relationship"] +"""]->(contact)
            """, 
            contact=elements["contact"],
            description=elements["description"],
            cnaName=elements["cnaName"])

    @staticmethod
    def _create_country(tx, elements):
        tx.run("""
            MATCH (cna:CNA { name:$cnaName })
            MERGE (country:Country { name:$name })
            MERGE (cna)-[:BASED_IN]->(country)
            """, 
            name=elements["name"],
            cnaName=elements["cnaName"])

    @staticmethod
    def _create_scope(tx, elements):
        tx.run("""
            MATCH (cna:CNA { name:$cnaName })
            MERGE (scope:Scope { description:$description })
            MERGE (cna)-[:"""+ elements["relationship"] +"""]->(scope)
            """, 
            description=elements["description"],
            cnaName=elements["cnaName"])

    @staticmethod
    def _create_cna_parent(tx, elements):
        tx.run("""
            MATCH (cna:CNA { name:$cnaName })
            MERGE (parentCNA:CNA { name:$cnaParentName, link:$cnaParentLink })
            MERGE (cna)<-[:OWNS_ORGANIZATION]-(parentCNA)
            """, 
            cnaParentName=elements["cnaParentName"],
            cnaParentLink=elements["cnaParentLink"],
            cnaName=elements["cnaName"])

    def write_cna(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_cna, elements)

    def write_disclosure_policy(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_disclosure_policy, elements)

    def write_organization_type(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_organization_type, elements)
    
    def write_security_advisory(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_security_advisory, elements)

    def write_contact_info(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_contact_info, elements)

    def write_country(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_country, elements)

    def write_scope(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_scope, elements)
    
    def write_cna_parent(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_cna_parent, elements)
            
    def write_cna_index(self):
        self.driver.execute_query("""CREATE INDEX cna_contact IF NOT EXISTS FOR (info:ContactInfo) ON (info.cnaEmail )""")

    def handle_cna(self, source_filename):
        with open(source_filename, mode='r') as file:
            data = json.load(file)
            cna_count = len(data["cnas"])
            
            self.write_cna_index()
            
            for idx,cna in enumerate(data["cnas"],1):
                self.printProgressBar(idx,cna_count,"CNA")

                label = ":".join(re.sub("\(.*\)","",role).replace(" ","").replace("-","") for role in cna["program_roles"])
                self.write_cna({
                    "name":cna["name"],
                    "link":cna["link_more_info"],
                    "label":label
                })
                for policy in cna["disclosure_policies"]:
                    self.write_disclosure_policy({
                        "link":policy["link"],
                        "description":policy["name"],
                        "cnaName":cna["name"]
                    })
                for org_type in cna["organization_types"]:
                    self.write_organization_type({
                        "type":org_type,
                        "cnaName":cna["name"]
                    })
                for sec_advisory in cna["security_advisories"]:
                    self.write_security_advisory({
                        "link":sec_advisory["link"],
                        "description":sec_advisory["name"],
                        "cnaName":cna["name"]
                    })
                for contact in cna["contacts"]:
                    self.write_contact_info({
                        "contact":contact["contact"],
                        "description":contact["name"],
                        "additionalLabel":contact["type"].capitalize(),
                        "relationship":"REACHABLE_BY_"+contact["type"].upper(),
                        "cnaName":cna["name"]
                    })
                self.write_country({
                    "name":cna["country"],
                    "cnaName":cna["name"]
                })
                for scope in cna["scopes"]:
                    scope["type"] = scope["type"].replace("-","_").upper()
                    print(scope["type"])
                    self.write_scope({
                        "description":scope["description"],
                        "relationship":"HAS_"+scope["type"]+"_SCOPE",
                        "cnaName":cna["name"]
                    })
                if "root" in cna:
                    self.write_cna_parent({
                        "cnaParentName":cna["root"]["name"],
                        "cnaParentLink":cna["root"]["link_more_info"],
                        "cnaName":cna["name"]
                    })
            
            print("")


    # ==============================================
    # =============== HANDLE CWE ===================
    # ==============================================

    @staticmethod
    def _create_cwe(tx, elements):
        tx.run("""
            MERGE (cwe:CWE { id:$id })
            SET cwe += { name:$name, description:$description, link:$link, extendedDescription:$extendedDescription, backgroundDetails:$backgroundDetails }
            """, 
            id=elements["id"],
            name=elements["name"],
            description=elements["description"],
            link=elements["link"],
            extendedDescription=elements["extendedDescription"],
            backgroundDetails=elements["backgroundDetails"])

    @staticmethod
    def _create_cwe_status(tx, elements):
        tx.run("""
            MATCH (cwe:CWE { id:$cweId })
            MERGE (status:Status { type:$type })
            MERGE (cwe)-[:HAS_STATUS]->(status)
            """, 
            type=elements["type"],
            cweId=elements["cweId"])

    @staticmethod
    def _create_cwe_related_cwe(tx, elements):
        relation = "{}-[:{}]-{}".format("<",elements["relationship"],"" if elements["direction"]=="Left" else "",elements["relationship"],">")
        tx.run("""
            MATCH (currentCwe:CWE { id:$cweId })
            MERGE (relatedCwe:CWE { id:$relatedCweId })
            MERGE (currentCwe)""" + relation + """(relatedCwe)
            """,
            relatedCweId=elements["relatedCweId"],
            direction=elements["direction"],
            cweId=elements["cweId"])

    @staticmethod
    def _create_weakness_ordinality(tx, elements):
        tx.run("""
            MATCH (cwe:CWE { id:$cweId })
            MERGE (weaknessOrdinality:WeaknessOrdinality { type:$type, description:$description })
            MERGE (cwe)-[r:HAS_WEAKNESS_ORDINALITY]->(weaknessOrdinality)
            SET r.description = $customDescription
            """, 
            type=elements["type"],
            description=elements["description"],
            customDescription=elements["customDescription"],
            cweId=elements["cweId"])

    @staticmethod
    def _create_cwe_alternative_term(tx, elements):
        tx.run("""
            MATCH (cwe:CWE { id:$cweId })
            MERGE (alternativeTerm:AlternativeTerm { name:$name })
            SET alternativeTerm.description=$description
            MERGE (cwe)-[:HAS_ALTERNATIVE_TERM]->(alternativeTerm)
            """, 
            name=elements["name"],
            description=elements["description"],
            cweId=elements["cweId"])

    @staticmethod
    def _create_phase(tx, elements):
        tx.run("""
            MATCH (cwe:CWE { id:$cweId })
            MERGE (phase:Phase { name:$name })
            MERGE (cwe)-[r:CAN_BE_INTRODUCED_DURING]->(status)
            SET r.description=$description
            """, 
            name=elements["name"],
            description=elements["description"],
            cweId=elements["cweId"])

    @staticmethod
    def _create_security_property(tx, elements):
        tx.run("""
            MERGE (:SecurityProperty { name:$name })
            """, 
            name=elements["name"])

    @staticmethod
    def _create_impact(tx, elements):
        tx.run("""
            MERGE (:Impact { name:$name })
            """, 
            name=elements["name"])
    
    @staticmethod
    def _remove_cwe_consequences(tx, elements):
        tx.run("""
            MATCH (cwe:CWE { id:$cweId })-[:HAS_COMMON_CONSEQUENCE]->(consequence:Consequence)
            DETACH DELETE consequence
            """, 
            cweId=elements["cweId"])

    @staticmethod
    def _create_cwe_consequence(tx, elements):
        tx.run( """
            MATCH (cwe:CWE { id:$cweId })
            CREATE (consequence:Consequence)
            SET consequence.description=$description
            MERGE (cwe)-[:HAS_COMMON_CONSEQUENCE]->(consequence)
            FOREACH (sec_name in $securityProperties | 
                MERGE (sec:SecurityProperty { name:sec_name }) 
                MERGE (consequence)-[:AFFECTS_SECURITY_PROPERTY]->(sec))
            FOREACH (impact_name in $impacts | 
                MERGE (impact:Impact { name:impact_name }) 
                MERGE (consequence)-[:HAS_IMPACT]->(impact))
            """, 
            description=elements["description"],
            securityProperties=elements["securityProperties"],
            impacts=elements["impacts"],
            cweId=elements["cweId"])
            
    @staticmethod
    def _create_detection_method(tx, elements):
        tx.run("""
            MATCH (cwe:CWE { id:$cweId })
            MERGE (detectionMethod:DetectionMethod { name:$name })
            MERGE (cwe)-[r:CAN_BE_DETECTED_BY]->(detectionMethod)
            SET r += { effectiveness:$effectiveness, description:$description }
            """, 
            name=elements["name"],
            description=elements["description"],
            effectiveness=elements["effectiveness"],
            cweId=elements["cweId"])

    @staticmethod
    def _create_cwe_mitigation(tx, elements):
        tx.run("""
            MATCH (cwe:CWE { id:$cweId })
            MERGE (mitigation:Mitigation { description:$description })
            MERGE (cwe)-[r:CAN_BE_MITIGATED_BY]->(mitigation)
            SET r.effectiveness=$effectiveness
            """, 
            description=elements["description"],
            effectiveness=elements["effectiveness"],
            cweId=elements["cweId"])

        if elements["phase"]:
            tx.run("""
                MATCH (mitigation:Mitigation { description:$description })
                MERGE (phase:Phase { name:$phase })
                MERGE (mitigation)-[:DURING_PHASE]->(phase)
                """, 
                phase=elements["phase"],
                description=elements["description"])

        if elements["strategy"]:
            tx.run("""
                MATCH (mitigation:Mitigation { description:$description })
                MERGE (strategy:Strategy { name:$strategy })
                MERGE (mitigation)-[:HAVING_STRATEGY]->(strategy)
                """, 
                strategy=elements["strategy"],
                description=elements["description"])

    @staticmethod
    def _create_functional_area(tx, elements):
        tx.run("""
            MATCH (cwe:CWE { id:$cweId })
            MERGE (functionalArea:FunctionalArea { name:$name })
            MERGE (cwe)-[:MAY_OCCURS_IN_FUNCTIONAL_AREA]->(functionalArea)
            """, 
            name=elements["name"],
            cweId=elements["cweId"])

    @staticmethod
    def _create_affected_resource(tx, elements):
        tx.run("""
            MATCH (cwe:CWE { id:$cweId })
            MERGE (resource:Resource { name:$name })
            MERGE (cwe)-[:AFFECTS_RESOURCE]->(resource)
            """, 
            name=elements["name"],
            cweId=elements["cweId"])

    @staticmethod
    def _create_cwe_related_capec(tx, elements):
        tx.run("""
            MATCH (cwe:CWE { id:$cweId })
            MERGE (capec:CAPEC { id:$capecId })
            MERGE (cwe)-[:HAS_RELATED_ATTACK_PATTERN]->(capec)
            """, 
            capecId=elements["capecId"],
            cweId=elements["cweId"])


    def write_cwe(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_cwe, elements)

    def write_cwe_status(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_cwe_status, elements)

    def write_cwe_related_cwe(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_cwe_related_cwe, elements)

    def write_weakness_ordinality(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_weakness_ordinality, elements)

    def write_cwe_alternative_term(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_cwe_alternative_term, elements)

    def write_phase(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_phase, elements)

    def write_security_property(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_security_property, elements)

    def write_impact(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_impact, elements)

    def write_cwe_consequence(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_cwe_consequence, elements)

    def delete_cwe_consequences(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._remove_cwe_consequences, elements)

    def write_detection_method(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_detection_method, elements)

    def write_cwe_mitigation(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_cwe_mitigation, elements)

    def write_functional_area(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_functional_area, elements)

    def write_affected_resource(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_affected_resource, elements)

    def write_cwe_related_capec(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_cwe_related_capec, elements)

    def write_cwe_index(self):
        self.driver.execute_query("""CREATE INDEX cwe_id IF NOT EXISTS FOR (cwe:CWE) ON (cwe.id )""")
    
    def handle_cwe(self, source_filename):
        ordinality_descriptions = {
            "Primary":"Where the weakness exists independent of other weaknesses",
            "Resultant":"Where the weakness is typically related to the presence of some other weaknesses",
            "Indirect":"Where the weakness is a quality issue that might indirectly make it easier to introduce security-relevant weaknesses or make them more difficult to detect"
        }

        related_cwe_regex = re.compile("^NATURE:(.*?):CWE ID:(.*?):VIEW ID:(.*?)(?::ORDINAL:(.*))?$")
        weakness_ordinality_regex = re.compile("^ORDINALITY:(.*?)(?::DESCRIPTION:(.*))?$")
        alternative_term_regex = re.compile("^TERM:(.*?)(?::DESCRIPTION:(.*))?$")
        phase_regex = re.compile("^PHASE:(.*?)(?::NOTE:(.*))?$")
        consequence_regex = re.compile("^(?:SCOPE:(.*?))?(?::IMPACT:(.*?))?(?::NOTE:(.*))?$")
        detection_method_regex = re.compile("^METHOD:(.*?):DESCRIPTION:(.*?)(?::EFFECTIVENESS:(.*))?$")
        mitigation_regex = re.compile("^(?:PHASE:(.*?))?(?::STRATEGY:(.*?))?[:]*(?:DESCRIPTION:(.*?))?(?::EFFECTIVENESS:(.*))?$")

        # Creating the indexes for the CWE nodes
        self.write_cwe_index()
        
        cwe_count = 0
        with open(source_filename, mode='r', encoding='utf-8') as csv_file:
            csv_reader = csv.DictReader(csv_file)
            cwe_count = sum(1 for row in csv_reader) - 1

        with open(source_filename, mode='r', encoding='utf-8') as csv_file:
            csv_reader = csv.DictReader(csv_file)
            for idx,cwe in enumerate(csv_reader,1):
                self.printProgressBar(idx,cwe_count,"CWE")

                self.write_cwe({
                    "id":cwe["CWE-ID"],
                    "name":cwe["Name"],
                    "description":cwe["Description"],
                    "link":"https://cwe.mitre.org/data/definitions/{}.html".format(cwe["CWE-ID"]),
                    "extendedDescription":cwe["Extended Description"] if cwe["Extended Description"] else None,
                    "backgroundDetails":cwe["Background Details"].replace("::","") if cwe["Background Details"] else None
                })
                if cwe["Status"]:
                    self.write_cwe_status({
                        "type":cwe["Status"],
                        "cweId":cwe["CWE-ID"]
                    })
                if cwe["Related Weaknesses"]:
                    for related_cwe in [elem for elem in cwe["Related Weaknesses"].split("::") if elem]:
                        sup = related_cwe_regex.search(related_cwe)
                        if sup.group(3) == "1000":
                            self.write_cwe_related_cwe({
                                "relatedCweId":sup.group(2),
                                "relationship":self.relationship[sup.group(1)]["relationship"],
                                "direction":self.relationship[sup.group(1)]["direction"],
                                "cweId":cwe["CWE-ID"]
                            })
                if cwe["Weakness Ordinalities"]:
                    for ordinality in [elem for elem in cwe["Weakness Ordinalities"].split("::") if elem]:
                        sup = weakness_ordinality_regex.search(ordinality)
                        self.write_weakness_ordinality({
                            "type":sup.group(1),
                            "description":ordinality_descriptions[sup.group(1)],
                            "customDescription":sup.group(2),
                            "cweId":cwe["CWE-ID"]
                        })
                if cwe["Alternate Terms"]:
                    for term in [elem for elem in cwe["Alternate Terms"].split("::") if elem]:
                        sup = alternative_term_regex.search(term)
                        self.write_cwe_alternative_term({
                            "name":sup.group(1),
                            "description":sup.group(2),
                            "cweId":cwe["CWE-ID"]
                        })
                if cwe["Modes Of Introduction"]:
                    for phase in [elem for elem in cwe["Modes Of Introduction"].split("::") if elem]:
                        sup = phase_regex.search(phase)
                        self.write_phase({
                            "name":sup.group(1),
                            "description":sup.group(2),
                            "cweId":cwe["CWE-ID"]
                        })

                if cwe["Common Consequences"]:
                    # Deleting the previous "Consequence" nodes before recreating the new ones. 
                    # This is necessary cause we are using the CREATE clause
                    self.delete_cwe_consequences({
                        "cweId":cwe["CWE-ID"]
                    })
                    for consequence in [elem for elem in cwe["Common Consequences"].split("::") if elem]:
                        sup = consequence_regex.search(consequence)
                        # for security_property in sup.group(1).split(":SCOPE:"):
                        #     self.write_security_property({
                        #         "name":security_property
                        #     })
                        # for impact in sup.group(2).split(":IMPACT:"):
                        #     self.write_impact({
                        #         "name":impact
                        #     })

                        self.write_cwe_consequence({
                            "description":sup.group(3),
                            "securityProperties":sup.group(1).split(":SCOPE:") if sup.group(1) else [],
                            "impacts":sup.group(2).split(":IMPACT:") if sup.group(2) else [],
                            "cweId":cwe["CWE-ID"]
                        })

                if cwe["Detection Methods"]:
                    for detection_method in [elem for elem in cwe["Detection Methods"].split("::") if elem]:
                        sup = detection_method_regex.search(detection_method)
                        self.write_detection_method({
                            "name":sup.group(1),
                            "description":sup.group(2),
                            "effectiveness":sup.group(3),
                            "cweId":cwe["CWE-ID"]
                        })

                if cwe["Potential Mitigations"]:
                    for mitigation in [elem for elem in cwe["Potential Mitigations"].split("::") if elem]:
                        if(sup := mitigation_regex.search(mitigation)) is not None:
                            self.write_cwe_mitigation({
                                "phase":sup.group(1),
                                "strategy":sup.group(2),
                                "description":sup.group(3),
                                "effectiveness":sup.group(4),
                                "cweId":cwe["CWE-ID"]
                            })

                if cwe["Functional Areas"]:
                    for area in [elem for elem in cwe["Functional Areas"].split("::") if elem]:
                        self.write_functional_area({
                            "name":area,
                            "cweId":cwe["CWE-ID"]
                        })
                if cwe["Affected Resources"]:
                    for resource in [elem for elem in cwe["Affected Resources"].split("::") if elem]:
                        self.write_affected_resource({
                            "name":resource,
                            "cweId":cwe["CWE-ID"]
                        })
                if cwe["Related Attack Patterns"]:
                    for capec in [elem for elem in cwe["Related Attack Patterns"].split("::") if elem]:
                        self.write_cwe_related_capec({
                            "capecId":capec,
                            "cweId":cwe["CWE-ID"]
                        })

            print("")

    # ==============================================
    # =============== HANDLE CAPEC =================
    # ==============================================

    @staticmethod
    def _create_capec(tx, elements):
        tx.run("""
            MERGE (capec:CAPEC { id:$id })
            SET capec += { name:$name, description:$description, link:$link }
            """, 
            id=elements["id"],
            name=elements["name"],
            description=elements["description"],
            link=elements["link"])

    @staticmethod
    def _create_capec_status(tx, elements):
        tx.run("""
            MATCH (capec:CAPEC { id:$capecId })
            MERGE (status:Status { type:$type })
            MERGE (capec)-[:HAS_STATUS]->(status)
            """, 
            type=elements["type"],
            capecId=elements["capecId"])

    @staticmethod
    def _create_capec_alternative_term(tx, elements):
        tx.run("""
            MATCH (capec:CAPEC { id:$capecId })
            MERGE (alternativeTerm:AlternativeTerm { name:$name })
            SET alternativeTerm.description=$description
            MERGE (capec)-[:HAS_ALTERNATIVE_TERM]->(alternativeTerm)
            """, 
            name=elements["name"],
            description=elements["description"],
            capecId=elements["capecId"])

    @staticmethod
    def _create_capec_scale_level(tx, elements):
        tx.run("""
            MATCH (capec:CAPEC { id:$capecId })
            MERGE (scaleLevel:ScaleLevel { level:$level })
            MERGE (capec)-[:"""+ elements["relationship"] +"""]->(scaleLevel)
            """, 
            level=elements["level"],
            capecId=elements["capecId"])

    @staticmethod
    def _create_execution_flow(tx, elements):
        tx.run("""
            MATCH (capec:CAPEC { id:$capecId })
            MERGE (ef:ExecutionFlow:"""+ elements["additionalLabel"] +""" { description:$description })
            SET ef.title=$title
            MERGE (capec)-[r:"""+ elements["relationship"] +"""]->(ef)
            SET r.flowStepNumber=$flowStepNumber
            """, 
            title=elements["title"],
            description=elements["description"],
            flowStepNumber=elements["flowStepNumber"],
            capecId=elements["capecId"])

    @staticmethod
    def _create_technique(tx, elements):
        additionalProperties = "title:$executionFlowTitle, " if elements["executionFlowTitle"] else ""
        tx.run("""
            MATCH (ef:ExecutionFlow { """ + additionalProperties + """ description:$executionFlowDescription })
            MERGE (technique:Technique { description:$description })
            MERGE (ef)-[:HAS_TECHNIQUE]->(technique)
            """, 
            executionFlowTitle=elements["executionFlowTitle"],
            executionFlowDescription=elements["executionFlowDescription"],
            description=elements["description"])

    @staticmethod
    def _create_prerequisite(tx, elements):
        tx.run("""
            MATCH (capec:CAPEC { id:$capecId })
            MERGE (prerequisite:Prerequisite { description:$description })
            MERGE (capec)-[:HAS_PREREQUISITE]->(prerequisite)
            """, 
            description=elements["description"],
            capecId=elements["capecId"])

    @staticmethod
    def _create_skill(tx, elements):
        tx.run("""
            MATCH (capec:CAPEC { id:$capecId })
            MERGE (skill:Skill { description:$description })
            MERGE (scaleLevel:ScaleLevel { level:$level })
            MERGE (capec)-[:REQUIRES_SKILL]->(skill)-[:REQUIRES_EXPERTISE_LEVEL]->(scaleLevel)
            """, 
            description=elements["description"],
            level=elements["level"],
            capecId=elements["capecId"])

    @staticmethod
    def _create_asset(tx, elements):
        tx.run("""
            MATCH (capec:CAPEC { id:$capecId })
            MERGE (asset:Asset { description:$description })
            MERGE (capec)-[:REQUIRES_ASSET]->(asset)
            """, 
            description=elements["description"],
            capecId=elements["capecId"])

    @staticmethod
    def _create_indicator(tx, elements):
        tx.run("""
            MATCH (capec:CAPEC { id:$capecId })
            MERGE (indicator:AttackIndicator { description:$description })
            MERGE (capec)-[:HAS_ATTACK_INDICATOR]->(indicator)
            """, 
            description=elements["description"],
            capecId=elements["capecId"])

    @staticmethod
    def _remove_capec_consequences(tx, elements):
        tx.run("""
            MATCH (capec:CAPEC { id:$capecId })-[:HAS_COMMON_CONSEQUENCE]->(consequence:Consequence)
            DETACH DELETE consequence
            """, 
            capecId=elements["capecId"])

    @staticmethod
    def _create_capec_consequence(tx, elements):
        tx.run( """
            MATCH (capec:CAPEC { id:$capecId })
            CREATE (consequence:Consequence)
            SET consequence.description=$description
            MERGE (capec)-[:HAS_COMMON_CONSEQUENCE]->(consequence)
            FOREACH (sec_name in $securityProperties | 
                MERGE (sec:SecurityProperty { name:sec_name }) 
                MERGE (consequence)-[:AFFECTS_SECURITY_PROPERTY]->(sec))
            FOREACH (impact_name in $impacts | 
                MERGE (impact:Impact { name:impact_name }) 
                MERGE (consequence)-[:HAS_IMPACT]->(impact))
            """, 
            description=elements["description"],
            securityProperties=elements["securityProperties"],
            impacts=elements["impacts"],
            capecId=elements["capecId"])

    @staticmethod
    def _create_capec_mitigation(tx, elements):
        tx.run("""
            MATCH (capec:CAPEC { id:$capecId })
            MERGE (mitigation:Mitigation { description:$description })
            MERGE (capec)-[:CAN_BE_MITIGATED_BY]->(mitigation)
            """, 
            description=elements["description"],
            capecId=elements["capecId"])

    @staticmethod
    def _create_capec_example(tx, elements):
        tx.run("""
            MATCH (capec:CAPEC { id:$capecId })
            MERGE (example:Example { description:$description })
            MERGE (capec)-[:HAS_EXAMPLE]->(example)
            """, 
            description=elements["description"],
            capecId=elements["capecId"])

    @staticmethod
    def _create_capec_related_capec(tx, elements):
        relation = "{}-[:{}]-{}".format("<",elements["relationship"],"" if elements["direction"]=="Left" else "",elements["relationship"],">")
        tx.run("""
            MATCH (currentCapec:CAPEC { id:$capecId })
            MERGE (relatedCapec:CAPEC { id:$relatedCapecId })
            MERGE (currentCapec)""" + relation + """(relatedCapec)
            """,
            relatedCapecId=elements["relatedCapecId"],
            direction=elements["direction"],
            capecId=elements["capecId"])

    def write_capec(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_capec, elements)

    def write_capec_status(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_capec_status, elements)

    def write_capec_alternative_term(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_capec_alternative_term, elements)

    def write_capec_scale_level(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_capec_scale_level, elements)

    def write_execution_flow(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_execution_flow, elements)

    def write_technique(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_technique, elements)

    def write_prerequisite(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_prerequisite, elements)

    def write_skill(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_skill, elements)

    def write_asset(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_asset, elements)

    def write_indicator(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_indicator, elements)

    def delete_capec_consequences(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._remove_capec_consequences, elements)

    def write_capec_consequence(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_capec_consequence, elements)

    def write_capec_mitigation(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_capec_mitigation, elements)

    def write_capec_example(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_capec_example, elements)

    def write_capec_related_capec(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_capec_related_capec, elements)
    
    def create_capec_index(self):
        self.driver.execute_query("""
            CREATE INDEX capec_id IF NOT EXISTS FOR (capec:CAPEC) ON (capec.id)
            """)

    def handle_capec(self, source_filename):
        alternative_term_regex = re.compile("^TERM:(.*?)(?::DESCRIPTION[:]*(.*))?$")
        execution_flow_regex = re.compile("^STEP:(.*?)(?::PHASE:(.*?))?(?::DESCRIPTION:(?:\[(.*?)\] )?(.*?))?(?::TECHNIQUE:(.*))?$")
        skill_regex = re.compile("^SKILL:(.*?)(?::LEVEL:(.*))?$")
        capec_consequence_regex = re.compile("^(?:SCOPE:(.*?))?(?:TECHNICAL IMPACT:(.*?))?(?::NOTE:(.*))?$")
        related_capec_regex = re.compile("^NATURE:(.*?):CAPEC ID:(.*)$")

        # Creating the indexes for the CAPEC nodes
        self.create_capec_index()
        
        capec_count = 0
        with open(source_filename, mode='r', encoding='utf-8') as csv_file:
            csv_reader = csv.DictReader(csv_file)
            capec_count = sum(1 for row in csv_reader) - 1

        with open(source_filename, mode='r', encoding='utf-8') as csv_file:
            csv_reader = csv.DictReader(csv_file)
            for idx,capec in enumerate(csv_reader,1):
                self.printProgressBar(idx,capec_count,"CAPEC")

                self.write_capec({
                    "id":capec["'ID"],
                    "name":capec["Name"],
                    "description":capec["Description"] if capec["Description"] else None,
                    "link":"https://capec.mitre.org/data/definitions/{}.html".format(capec["'ID"])
                })
                if capec["Status"]:
                    self.write_capec_status({
                        "type":capec["Status"],
                        "capecId":capec["'ID"]
                    })
                if capec["Alternate Terms"]:
                    for term in [elem for elem in capec["Alternate Terms"].replace(":::","::").split("::") if elem]:
                        sup = alternative_term_regex.search(term)
                        self.write_capec_alternative_term({
                            "name":sup.group(1),
                            "description":sup.group(2) if sup.group(2) else None,
                            "capecId":capec["'ID"]
                        })
                if capec["Likelihood Of Attack"]:
                    self.write_capec_scale_level({
                        "level":capec["Likelihood Of Attack"],
                        "relationship":"HAS_ATTACK_LIKELIHOOD",
                        "capecId":capec["'ID"]
                    })
                if capec["Typical Severity"]:
                    self.write_capec_scale_level({
                        "level":capec["Typical Severity"],
                        "relationship":"HAS_TYPICAL_SEVERITY",
                        "capecId":capec["'ID"]
                    })
                if capec["Execution Flow"]:
                    count_step = 1
                    for flow in [elem for elem in capec["Execution Flow"].split("::") if elem]:
                        sup = execution_flow_regex.search(flow)

                        self.write_execution_flow({
                            "title":sup.group(3),
                            "description":sup.group(4),
                            "additionalLabel":sup.group(2).capitalize(),
                            "relationship":"HAS_{}_FLOW".format(sup.group(2).upper()),
                            "flowStepNumber":count_step,
                            "capecId":capec["'ID"]
                        })
                        if sup.group(5):
                            for technique in sup.group(5).split(":TECHNIQUE:"):
                                self.write_technique({
                                    "executionFlowTitle":sup.group(3),
                                    "executionFlowDescription":sup.group(4),
                                    "description":technique
                                })

                        count_step += 1

                if capec["Prerequisites"]:
                    for prerequisite in [elem for elem in capec["Prerequisites"].split("::") if elem]:
                        self.write_prerequisite({
                            "description":prerequisite,
                            "capecId":capec["'ID"]
                        })
                if capec["Skills Required"]:
                    for skill in [elem for elem in capec["Skills Required"].split("::") if elem]:
                        sup = skill_regex.search(skill)
                        if sup:
                            self.write_skill({
                                "description":sup.group(1),
                                "level":sup.group(2),
                                "capecId":capec["'ID"]
                            })
                if capec["Resources Required"]:
                    for resource in [elem for elem in capec["Resources Required"].split("::") if elem]:
                        self.write_asset({
                            "description":resource,
                            "capecId":capec["'ID"]
                        })
                if capec["Indicators"]:
                    for indicator in [elem for elem in capec["Indicators"].split("::") if elem]:
                        self.write_indicator({
                            "description":indicator,
                            "capecId":capec["'ID"]
                        })

                if capec["Consequences"]:
                    # Deleting the previous "Consequence" nodes before recreating the new ones. 
                    # This is necessary cause we are using the CREATE clause
                    self.delete_capec_consequences({
                        "capecId":capec["'ID"]
                    })
                    for consequence in [elem for elem in capec["Consequences"].split("::") if elem]:
                        # Edge case. The easiest and fastest way is to hardcoded it.
                        if capec["'ID"] == "508":
                            consequence = consequence.split(":LIKELIHOOD:")[0]
                        sup = capec_consequence_regex.search(consequence)
                        self.write_capec_consequence({
                            "description":sup.group(3),
                            "securityProperties":sup.group(1).split(":SCOPE:") if sup.group(1) else None,
                            "impacts":sup.group(2).split(":TECHNICAL IMPACT:") if sup.group(2) else None,
                            "capecId":capec["'ID"]
                        })

                if capec["Mitigations"]:
                    for mitigation in [elem for elem in capec["Mitigations"].split("::") if elem]:
                        # Even though some of the descriptions contain also the "phase" in which the mitigation might be applied, 
                        # they don't follow any previous standards (i.e. hard to select even using regexes).
                        #
                        # Example of phases: Operation, Operational, Implementation, Design, Configuration, Usage,
                        # Pre-design, Pre-design through Build, Assurance
                        self.write_capec_mitigation({
                            "description":mitigation,
                            "capecId":capec["'ID"]
                        })
                if capec["Example Instances"]:
                    for example in [elem for elem in capec["Example Instances"].split("::") if elem]:
                        self.write_capec_example({
                            "description":example,
                            "capecId":capec["'ID"]
                        })
                if capec["Related Attack Patterns"]:
                    for related_capec in [elem for elem in capec["Related Attack Patterns"].split("::") if elem]:
                        sup = related_capec_regex.search(related_capec)
                        self.write_capec_related_capec({
                            "relatedCapecId":sup.group(2),
                            "relationship":self.relationship[sup.group(1)]["relationship"],
                            "direction":self.relationship[sup.group(1)]["direction"],
                            "capecId":capec["'ID"]
                        })
                
                # No need to process the "Related Weaknesses" field (i.e. CWE) since it's already been done in the CWE part.

            print("")

    # ==============================================
    # =============== HANDLE EPSS ==================
    # ==============================================
    
    def write_epss(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_epss, elements)
    
    def clean_epss(self):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._delete_epss)
    
    @staticmethod
    def _delete_epss(tx):
        tx.run("""MATCH (epss:EPSS) DETACH DELETE epss""")
        
    
    @staticmethod
    def _create_epss(tx, elements):
        tx.run("""
               MATCH (cve:CVE { id:$cveId })
               MERGE (epss:EPSS { probability:$probability, percentile:$percentile})
               MERGE (cve)-[:HAS_EPSS]->(epss)
               """,
               cveId=elements["cveId"],
               probability=elements["probability"],
               percentile=elements["percentile"])
        
    def handle_epss(self, source_filename):
        
        #we need to first remove existing epss
        self.clean_epss()
        
        total=0
        with open(source_filename, 'r', encoding="utf-8") as file:
            reader = csv.reader(file, delimiter=',')
            for row in reader:
                total += 1
        
        total = total - 2
        
        with open(source_filename, 'r', encoding="utf-8") as file:
            reader = csv.reader(file, delimiter=',')
            # Skip the first row (comment with version and last update date)
            next(reader)
            # Read the second row (column headers)
            headers = next(reader)
            
            idx=0
            
            for row in reader:
                # Create a dictionary using the headers as keys and row values
                row_dict = dict(zip(headers, row))
                self.printProgressBar(idx,total,"EPSS")
                
                self.write_epss({
                    "cveId":row_dict["cve"],
                    "probability":float(row_dict["epss"]),
                    "percentile":float(row_dict["percentile"]),
                })
                idx += 1
                
            print("")
    
    # ==============================================
    # =============== HANDLE SOURCES ===============
    # ==============================================
    
    @staticmethod
    def _create_source_v2_acceptance_level(tx, elements):
        tx.run("""
            MATCH (cna:CNA)-[:REACHABLE_BY_EMAIL]->(:ContactInfo { contact:$cnaEmail })
            MERGE (al:V2_ACCEPTANCE_LEVEL { description:$description, lastModified:$lastModified })
            MERGE (cna)-[:HAS_V2_ACCEPTANCE_LEVEL]->(al)
            """, 
            cnaEmail=elements["email"],
            description=elements["description"],
            lastModified=elements["lastModified"])
    
    @staticmethod
    def _create_source_v3_acceptance_level(tx, elements):
        tx.run("""
            MATCH (cna:CNA)-[:REACHABLE_BY_EMAIL]->(:ContactInfo { contact:$cnaEmail })
            MERGE (al:V3_ACCEPTANCE_LEVEL { description:$description, lastModified:$lastModified })
            MERGE (cna)-[:HAS_V3_ACCEPTANCE_LEVEL]->(al)
            """, 
            cnaEmail=elements["email"],
            description=elements["description"],
            lastModified=elements["lastModified"])
    
    @staticmethod
    def _create_source_cwe_acceptance_level(tx, elements):
        tx.run("""
            MATCH (cna:CNA)-[:REACHABLE_BY_EMAIL]->(:ContactInfo { contact:$cnaEmail })
            MERGE (al:CWE_ACCEPTANCE_LEVEL { description:$description, lastModified:$lastModified })
            MERGE (cna)-[:HAS_CWE_ACCEPTANCE_LEVEL]->(al)
            """, 
            cnaEmail=elements["email"],
            description=elements["description"],
            lastModified=elements["lastModified"])
            
    def write_source_v2_acceptance_level(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_source_v2_acceptance_level, elements)
    
    def write_source_v3_acceptance_level(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_source_v3_acceptance_level, elements)
    
    def write_source_cwe_acceptance_level(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_source_cwe_acceptance_level, elements)
    
    def handle_sources(self, source_filename):
        with open(source_filename, mode='r') as file:
            data = json.load(file)
            source_count = len(data["sources"])
            for idx,source in enumerate(data["sources"],1):
                self.printProgressBar(idx,source_count,"sources")
                    
                if "v2AcceptanceLevel" in source:
                    self.write_source_v2_acceptance_level({
                        "email": source["contactEmail"],
                        "description": source["v2AcceptanceLevel"]["description"],
                        "lastModified": source["v2AcceptanceLevel"]["lastModified"]
                    })
                    
                if "v3AcceptanceLevel" in source:
                    self.write_source_v3_acceptance_level({
                        "email": source["contactEmail"],
                        "description": source["v3AcceptanceLevel"]["description"],
                        "lastModified": source["v3AcceptanceLevel"]["lastModified"]
                    })
                
                if "cweAcceptanceLevel" in source:
                    self.write_source_cwe_acceptance_level({
                        "email": source["contactEmail"],
                        "description": source["cweAcceptanceLevel"]["description"],
                        "lastModified": source["cweAcceptanceLevel"]["lastModified"]
                    })
            print("")

    # ==============================================
    # =============== HANDLE CPE ===================
    # ==============================================
    
    @staticmethod
    def _create_cpe_title(tx, elements):
        tx.run("""
            MATCH (:CVE)-[:AFFECTS { cpe23Uri:$cpeName }]->(p:Product)
            MERGE (ti:Title { title:$title, language:$language })
            MERGE (p)-[:HAS_TITLE]->(ti)
            """, 
            cpeName=elements["cpeName"],
            title=elements["title"],
            language=elements["language"])
        
    @staticmethod
    def _create_cpe_refs(tx, elements):
        tx.run("""
            MATCH (:CVE)-[:AFFECTS { cpe23Uri:$cpeName }]->(p:Product)
            MERGE (ref:Ref { ref:$ref})
            MERGE (p)-[:HAS_REF {type: $type}]->(ref)
            """, 
            cpeName=elements["cpeName"],
            ref=elements["ref"],
            type=elements["type"])
    
    def write_cpe_title(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_cpe_title, elements)
            
    def write_cpe_refs(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_cpe_refs, elements)

    def handle_cpe(self, cpe_filename):
        with open(cpe_filename, mode='r') as file:
            data = json.load(file)
            product_count = len(data["products"])
            for idx,product in enumerate(data["products"],1):
                self.printProgressBar(idx,product_count,"products")     
                cpe=product["cpe"]
                
                if not cpe["deprecated"]:
                    for title in cpe["titles"]:
                        self.write_cpe_title({
                            "cpeName": cpe["cpeName"],
                            "title": title["title"],
                            "language": title["lang"]
                        })
                    
                    
                    #TODO little fix here if ref is there or not
                    if "refs" in cpe:
                        for ref in cpe["refs"]:
                            if "type" in ref:
                                self.write_cpe_refs({
                                    "cpeName": cpe["cpeName"],
                                    "ref": ref["ref"],
                                    "type": ref["type"]
                                })
                
            print("")
    
    # ==============================================
    # =============== HANDLE CVE ===================
    # ==============================================

    @staticmethod
    def _create_cve(tx, elements):
        tx.run("""
            MERGE (cve:CVE { id:$id, publishedDate:$publishedDate, lastModifiedDate:$lastModifiedDate })
            SET cve.description=$description
            """,    
            id=elements["id"],
            description=elements["description"],
            publishedDate=elements["publishedDate"],
            lastModifiedDate=elements["lastModifiedDate"])

    @staticmethod
    def _create_cve_related_cna(tx, elements):
        tx.run("""
            MATCH (cve:CVE { id:$cveId })
            MATCH (cna:CNA)-[:REACHABLE_BY_EMAIL]->(:ContactInfo { contact:$cnaEmail })
            MERGE (cve)<-[:ASSIGNED]-(cna)
            """, 
            cnaEmail=elements["cnaEmail"],
            cveId=elements["cveId"])

    @staticmethod
    def _create_cve_related_cwe(tx, elements):
        tx.run("""
            MATCH (cve:CVE { id:$cveId })
            MERGE (cwe:CWE { id:$cweId })
            MERGE (cve)-[:HAS_WEAKNESS]->(cwe)
            """, 
            cweId=elements["cweId"],
            cveId=elements["cveId"])
        
    @staticmethod
    def _create_metric(tx, elements):
        tx.run('''
            MATCH (cve:CVE { id:$cveId })
            MERGE (metric:Metric:'''+ elements["severity"] +''' { vector:$vector, baseScore:$baseScore })
            MERGE (cve)-[:HAS_METRIC { exploitabilityScore:$exploitabilityScore, impactScore:$impactScore}]->(metric)
            ''', 
            vector=elements["vector"],
            baseScore=elements["baseScore"],
            exploitabilityScore=elements["exploitabilityScore"],
            impactScore=elements["impactScore"],
            cveId=elements["cveId"])

    @staticmethod
    def _create_reference(tx, elements):
        # MATCH (ref:Reference:''' + elements["tags"] + ''') WHERE SIZE(LABELS(ref)) = $countLabels
        tx.run("""
            MATCH (cve:CVE { id:$cveId })
            MERGE (ref { url:$url })
            MERGE (cve)-[:HAS_LINK_TO]->(ref)
            """,
            url=elements["url"],
            cveId=elements["cveId"])

    @staticmethod
    def _create_vendor_and_product(tx, elements):
        tx.run('''
            MERGE (vnd:Vendor { name:$vendorName } )
            MERGE (prd:Product { name:$productName, type:$productType } )
            MERGE (vnd)-[:OWN]->(prd)
            ''',
            vendorName=elements["vendorName"],
            productName=elements["productName"],
            productType=elements["productType"])

    @staticmethod
    def _create_version(tx, elements):
        tx.run('''
            MATCH (cve:CVE { id:$cveId })
            MATCH (prd:Product { name:$productName } )
            MERGE (cve)-[aff:AFFECTS { vulnerable:$vulnerable, versionStartIncluding:$versionStartIncluding, cpe23Uri:$cpe23Uri } ]->(prd)
            SET aff.versionEndExcluding=$versionEndExcluding
            ''',
            cveId=elements["cveId"],
            productName=elements["productName"],
            vulnerable=elements["vulnerable"],
            cpe23Uri=elements["cpe23Uri"],
            versionStartIncluding=elements["versionStartIncluding"],
            versionEndExcluding=elements["versionEndExcluding"])
                       
    def write_cve(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_cve, elements)

    def write_cve_related_cna(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_cve_related_cna, elements)

    def write_cve_related_cwe(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_cve_related_cwe, elements)
    
    def write_metric(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_metric, elements)

    def write_reference(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_reference, elements)

    def write_vendor_and_product(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_vendor_and_product, elements)

    def write_version(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_version, elements)
            
    def create_cve_index(self):
        self.driver.execute_query("""
            CREATE TEXT INDEX cve_id IF NOT EXISTS FOR (cve:CVE) ON (cve.id)
            """)

    def handle_cve(self, source_filename):
        with open(source_filename, mode="r", encoding='utf-8') as file:
            
            self.create_cve_index()
            
            data = json.load(file)
            cve_count = len(data["vulnerabilities"])
            for idx,cve in enumerate(data["vulnerabilities"],1):
                self.printProgressBar(idx,cve_count,"CVE")

                self.write_cve({
                    "id":cve["cve"]["id"],
                    "description":cve["cve"]["descriptions"][0]["value"],
                    "publishedDate":cve["cve"]["published"],
                    "lastModifiedDate":cve["cve"]["lastModified"],
                })
                # Before run it be sure to have run "handle_cna" first!
                self.write_cve_related_cna({
                    "cnaEmail":cve["cve"]["sourceIdentifier"],
                    "cveId":cve["cve"]["id"]
                })
                # If there are no CWE related the "description" array is empty, so no additional check needed.
                if "weaknesses" in cve["cve"]:
                    for cwe in cve["cve"]["weaknesses"]:
                        self.write_cve_related_cwe({
                            "cweId":cwe["description"][0]["value"].replace("CWE-",""),
                            "cveId":cve["cve"]["id"]
                        })
                    
                if "cvssMetricV30" in cve["cve"]["metrics"]:
                    self.write_metric({
                        "vector":cve["cve"]["metrics"]["cvssMetricV30"][0]["cvssData"]["vectorString"].replace("CVSS:3.0/",""),
                        "baseScore":cve["cve"]["metrics"]["cvssMetricV30"][0]["cvssData"]["baseScore"],
                        "severity":cve["cve"]["metrics"]["cvssMetricV30"][0]["cvssData"]["baseSeverity"].capitalize(),
                        "exploitabilityScore":cve["cve"]["metrics"]["cvssMetricV30"][0]["exploitabilityScore"],
                        "impactScore":cve["cve"]["metrics"]["cvssMetricV30"][0]["impactScore"],
                        "cveId":cve["cve"]["id"]
                    })
                if "cvssMetricV31" in cve["cve"]["metrics"]:
                    self.write_metric({
                        "vector":cve["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["vectorString"].replace("CVSS:3.1/",""),
                        "baseScore":cve["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"],
                        "severity":cve["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseSeverity"].capitalize(),
                        "exploitabilityScore":cve["cve"]["metrics"]["cvssMetricV31"][0]["exploitabilityScore"],
                        "impactScore":cve["cve"]["metrics"]["cvssMetricV31"][0]["impactScore"],
                        "cveId":cve["cve"]["id"]
                    })
                    
                if "references" in cve["cve"]:
                    for ref in cve["cve"]["references"]:
                        if "tags" in ref:
                            additionalLabels = ":Ref".join(map(lambda tag: tag.title(),ref["tags"])).replace(" ","").replace("/","").replace("\\","").replace("|","").replace("-","")
                            additionalLabels = additionalLabels if not additionalLabels else ":" + additionalLabels
                        else:
                            additionalLabels = ""
                        self.write_reference({
                            "labels":":Reference" + additionalLabels,
                            "url":ref["url"],
                            "cveId":cve["cve"]["id"]
                        })
                # TODO - Possible integration with https://nvd.nist.gov/developers/products
                #Be sure to have run "handle_cpe" first!
                if("configurations" in cve["cve"]):
                    for configuration in cve["cve"]["configurations"]:
                        for node in configuration["nodes"]:
                            for cpe in node["cpeMatch"]:
                                
                                cpe_elements = cpe["criteria"].split(":")

                                self.write_vendor_and_product({
                                    "vendorName":cpe_elements[3],
                                    "productName":cpe_elements[4],
                                    "productType":("Application" if cpe_elements[2]=="a" else "Hardware" if cpe_elements[2]=="h" else "Operating Systems")
                                })

                                # TODO - At the moment the graph doesn't model the combination AND/OR of products
                                # (es. CVE-2019-5163, CVE-2021-43803) or CVE-2017-20026 (where there's no "versionStartIncluding")
                                if "versionStartIncluding" in cpe:
                                    self.write_version({
                                        "cveId":cve["cve"]["id"],
                                        "productName":cpe_elements[4],
                                        "vulnerable":cpe["vulnerable"],
                                        "cpe23Uri":cpe["criteria"],
                                        "versionStartIncluding":cpe["versionStartIncluding"],
                                        "versionEndExcluding":cpe["versionEndExcluding"] if "versionEndExcluding" in cpe else None
                                    })

            print("")

    # ==============================================
    # =============== HANDLE MITRE ===================
    # ==============================================
    
    @staticmethod
    def _create_tactic(tx, elements):
        tx.run("""
            MERGE (tactic:TACTIC { id:$id, name:$name, description:$description, link:$link })
            """, 
            id=elements["external_id"],
            name=elements["name"],
            description=elements["description"],
            link=elements["link"])

    @staticmethod
    def _create_mitre_technique(tx, elements):
        tx.run("""
            MATCH (tactic:TACTIC { id:$tacId })
            MERGE (tec:AdversaryTechnique { id:$id, name:$name, description:$description, link:$link})
            MERGE (tactic)-[:HAS_MITRE_TECHNIQUE]->(tec)
            """, 
            tacId=elements["tac_external_id"],
            id=elements["external_id"],
            name=elements["name"],
            description=elements["description"],
            link=elements["link"])

    def write_tactic(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_tactic, elements)

    def write_mitre_technique(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_mitre_technique, elements)

    # ==============================================
    # =============== HANDLE GROUPS ===================
    # ==============================================

    
    @staticmethod
    def _create_GROUP(tx, elements):
        tx.run("MERGE (x:THREAT_ACTOR { name:$name, description:$description, link:$link })", 
            name=elements["name"],
            description=elements["description"],
            link=elements["link"])

    @staticmethod
    def _create_alias(tx, elements):
        tx.run("""
                MATCH (x:THREAT_ACTOR { name:$name })
                MERGE (y:THREAT_ACTOR_ALIAS { name:$alias})
                MERGE (x)-[:HAS_ALIAS]->(y)
                """,
                name = elements["name"],
                alias=elements["alias"])

    @staticmethod
    def _create_group_with_technique(tx, elements):
        tx.run("""
                MATCH (x:AdversaryTechnique { id:$id })
                MERGE (y:THREAT_ACTOR { name:$name, description:$description, link:$link})
                MERGE (x)-[:IS_USED_BY]->(y)
                """,
                id = elements["tecId"],
                name = elements["name"],
                description = elements["description"],
                link = elements["link"])
              
    def write_group(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_GROUP, elements)

    def write_alias(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_alias, elements)

    def write_group_with_technique(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_group_with_technique, elements)
    
    def handle_group(self, json):
        self.write_group({
            "name":json.get('name'),
            "description":json.get("description"),
            "link":json.get("link")
        })
        for item in json.get('aliases'):
            self.write_alias({
                'name':json.get('name'),
                'alias':item
            })
    
    def first_mitre_run(self, json):
        mitre_attack_data = MitreAttackData("enterprise-attack.json")
        techniques = []
        tactics = mitre_attack_data.get_tactics(remove_revoked_deprecated=True)
        tactics_new = []
        for item in tactics:
            for item2 in item.get('external_references'):
                if item2.get('source_name') == "mitre-attack":
                    tactics_new.append({
                        'external_id':item2.get('external_id'),
                        'name':item.get('name'),
                        'description':item.get('description'),
                        'link':item2.get('url'),
                        "short-name":item.get('x_mitre_shortname'),
                        'techniques':[]
                    })
        for tactic in tactics_new:
            techniques = mitre_attack_data.get_techniques_by_tactic(tactics_new[0].get('short-name'), "enterprise-attack", remove_revoked_deprecated=True)
            for tec in techniques:
                for tec2 in tec.get('external_references'):
                    if tec2.get('source_name') == "mitre-attack":
                        tactic.get('techniques').append({
                            'external_id':tec2.get('external_id'),
                            'name':tec.get('name'),
                            'description':tec.get('description'),
                            'link':tec2.get('url'),
                        })
        for tac in tactics_new:
            self.write_tactic({
                'external_id':tac.get('external_id'),
                'name':tac.get('name'),
                'description':tac.get('description'),
                'link':tac.get('link')
            }) 
            for tec in tac.get('techniques'):
                self.write_mitre_technique({
                    'tac_external_id':tac.get('external_id'),
                    'external_id':tec.get('external_id'),
                    'name':tec.get('name'),
                    'description':tec.get('description'),
                    'link':tec.get('link')
            })
        gg = mitre_attack_data.get_all_groups_using_all_techniques()
        for id, groups in gg.items():
            attack_id = mitre_attack_data.get_attack_id(id)
            for gg in groups:
                for ex in gg.get('object').get('external_references'):
                    if ex.get('source_name') == "mitre-attack":
                        cyberGraph.write_group_with_technique({
                            "name":gg.get('object').get('name'),
                            "description":gg.get('object').get('description'),
                            "link":ex.get('url'),
                            "tecId":attack_id,
                    })
            print(f"* {attack_id} - used by {len(groups)} {'group' if len(groups) == 1 else 'groups'}")
        groups = mitre_attack_data.get_groups(remove_revoked_deprecated=True)
        print("** Analysis ended**")

if __name__ == "__main__":
    load_dotenv()

    neo4j_uri = os.getenv('NEO4J_URI')
    neo4j_username = os.getenv('NEO4J_USERNAME')
    neo4j_password = os.getenv('NEO4J_PASSWORD')

    cyberGraph = CyberGraph(neo4j_uri, neo4j_username, neo4j_password)

    cyberGraph.handle_cna("cna.json")
    cyberGraph.handle_cwe("cwe.csv")
    cyberGraph.handle_capec("capec.csv")
    cyberGraph.handle_cve("dump.json")
    cyberGraph.handle_epss("epss.csv")
    cyberGraph.first_mitre_run("enterprise-attack.json")
    #cyberGraph.handle_sources("sources.json")
    #cyberGraph.handle_cpe("cpe.json")

    cyberGraph.close()
    
import requests
import math
import os
from mitreattack.stix20 import MitreAttackData
from dotenv import load_dotenv
from neo4j import GraphDatabase
import time
import csv
import re
import json
import sys


class CyberGraph:

    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        self.db="neo4j"

    def close(self):
        self.driver.close()

    # ==============================================
    # ============ INTERNAL UTILITIES ==============
    # ==============================================

    def printProgressBar(self, value, max, label):
        n_bar = 40 # Size of progress bar
        sup= value/max
        sys.stdout.write('\r')
        bar = '█' * int(n_bar * sup)
        bar = bar + '-' * int(n_bar * (1-sup))

        sys.stdout.write(f"{label.ljust(10)} | [{bar:{n_bar}s}] {int(100 * sup)}% ")
        sys.stdout.flush()

    # ==============================================
    # ===== COMMON VARIABLES (Of: CWE, CAPEC) ======
    # ==============================================

    relationship = {
        "ChildOf": {                    # (current)<--(related_cwe)
            "relationship":"PARENT_OF",
            "direction":"Left"
        },           
        "CanPrecede":{                  # (current)-->(related_cwe)
            "relationship":"CAN_PRECEDE",
            "direction":"Right"
        },
        "CanFollow":{                    # (current)<--(related_cwe)
            "relationship":"CAN_PRECEDE",
            "direction":"Left"
        },
        "PeerOf":{                      # (current)--(related_cwe)  --> as default
            "relationship":"PEER_OF",  
            "direction":"Right"
        }, 
        "CanAlsoBe":{                   # (current)--(related_cwe)  --> as default
            "relationship":"CAN_ALSO_BE",
            "direction":"Right"
        },
        "Requires":{                    # (current)-->(related_cwe)
            "relationship":"REQUIRES",
            "direction":"Right"
        }
    }

    # ==============================================
    # =============== HANDLE CNA ===================
    # ==============================================

    @staticmethod
    def _create_cna(tx, elements):
        tx.run("MERGE (cna:CNA { name:$name, link:$link }) SET cna:"+ elements["label"], 
            name=elements["name"],
            link=elements["link"])

    @staticmethod
    def _create_disclosure_policy(tx, elements):
        tx.run("""
            MATCH (cna:CNA { name:$cnaName })
            MERGE (dp:DisclosurePolicy { link:$link, description:$description })
            MERGE (cna)-[:HAS_DISCLOSURE_POLICY]->(dp)
            """, 
            link=elements["link"],
            description=elements["description"],
            cnaName=elements["cnaName"])

    @staticmethod
    def _create_organization_type(tx, elements):
        tx.run("""
            MATCH (cna:CNA { name:$cnaName })
            MERGE (ot:OrganizationType { type:$type })
            MERGE (cna)-[:WORKS_IN_THE_FIELD_OF]->(ot)
            """, 
            type=elements["type"],
            cnaName=elements["cnaName"])

    @staticmethod
    def _create_security_advisory(tx, elements):
        tx.run("""
            MATCH (cna:CNA { name:$cnaName })
            MERGE (sa:SecurityAdvisory { link:$link, description:$description })
            MERGE (cna)-[:HAS_SECURITY_ADVISORY]->(sa)
            """, 
            link=elements["link"],
            description=elements["description"],
            cnaName=elements["cnaName"])

    @staticmethod
    def _create_contact_info(tx, elements):
        tx.run("""
            MATCH (cna:CNA { name:$cnaName })
            MERGE (contact:ContactInfo:"""+ elements["additionalLabel"] +""" { contact:$contact, description:$description })
            MERGE (cna)-[:"""+ elements["relationship"] +"""]->(contact)
            """, 
            contact=elements["contact"],
            description=elements["description"],
            cnaName=elements["cnaName"])

    @staticmethod
    def _create_country(tx, elements):
        tx.run("""
            MATCH (cna:CNA { name:$cnaName })
            MERGE (country:Country { name:$name })
            MERGE (cna)-[:BASED_IN]->(country)
            """, 
            name=elements["name"],
            cnaName=elements["cnaName"])

    @staticmethod
    def _create_scope(tx, elements):
        tx.run("""
            MATCH (cna:CNA { name:$cnaName })
            MERGE (scope:Scope { description:$description })
            MERGE (cna)-[:"""+ elements["relationship"] +"""]->(scope)
            """, 
            description=elements["description"],
            cnaName=elements["cnaName"])

    @staticmethod
    def _create_cna_parent(tx, elements):
        tx.run("""
            MATCH (cna:CNA { name:$cnaName })
            MERGE (parentCNA:CNA { name:$cnaParentName, link:$cnaParentLink })
            MERGE (cna)<-[:OWNS_ORGANIZATION]-(parentCNA)
            """, 
            cnaParentName=elements["cnaParentName"],
            cnaParentLink=elements["cnaParentLink"],
            cnaName=elements["cnaName"])

    def write_cna(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_cna, elements)

    def write_disclosure_policy(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_disclosure_policy, elements)

    def write_organization_type(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_organization_type, elements)
    
    def write_security_advisory(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_security_advisory, elements)

    def write_contact_info(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_contact_info, elements)

    def write_country(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_country, elements)

    def write_scope(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_scope, elements)
    
    def write_cna_parent(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_cna_parent, elements)
            
    def write_cna_index(self):
        self.driver.execute_query("""CREATE INDEX cna_contact IF NOT EXISTS FOR (info:ContactInfo) ON (info.cnaEmail )""")

    def handle_cna(self, source_filename):
        with open(source_filename, mode='r') as file:
            data = json.load(file)
            cna_count = len(data["cnas"])
            
            self.write_cna_index()
            
            for idx,cna in enumerate(data["cnas"],1):
                self.printProgressBar(idx,cna_count,"CNA")

                label = ":".join(re.sub("\(.*\)","",role).replace(" ","").replace("-","") for role in cna["program_roles"])
                self.write_cna({
                    "name":cna["name"],
                    "link":cna["link_more_info"],
                    "label":label
                })
                for policy in cna["disclosure_policies"]:
                    self.write_disclosure_policy({
                        "link":policy["link"],
                        "description":policy["name"],
                        "cnaName":cna["name"]
                    })
                for org_type in cna["organization_types"]:
                    self.write_organization_type({
                        "type":org_type,
                        "cnaName":cna["name"]
                    })
                for sec_advisory in cna["security_advisories"]:
                    self.write_security_advisory({
                        "link":sec_advisory["link"],
                        "description":sec_advisory["name"],
                        "cnaName":cna["name"]
                    })
                for contact in cna["contacts"]:
                    self.write_contact_info({
                        "contact":contact["contact"],
                        "description":contact["name"],
                        "additionalLabel":contact["type"].capitalize(),
                        "relationship":"REACHABLE_BY_"+contact["type"].upper(),
                        "cnaName":cna["name"]
                    })
                self.write_country({
                    "name":cna["country"],
                    "cnaName":cna["name"]
                })
                for scope in cna["scopes"]:
                    scope["type"] = scope["type"].replace("-","_").upper()
                    print(scope["type"])
                    self.write_scope({
                        "description":scope["description"],
                        "relationship":"HAS_"+scope["type"]+"_SCOPE",
                        "cnaName":cna["name"]
                    })
                if "root" in cna:
                    self.write_cna_parent({
                        "cnaParentName":cna["root"]["name"],
                        "cnaParentLink":cna["root"]["link_more_info"],
                        "cnaName":cna["name"]
                    })
            
            print("")


    # ==============================================
    # =============== HANDLE CWE ===================
    # ==============================================

    @staticmethod
    def _create_cwe(tx, elements):
        tx.run("""
            MERGE (cwe:CWE { id:$id })
            SET cwe += { name:$name, description:$description, link:$link, extendedDescription:$extendedDescription, backgroundDetails:$backgroundDetails }
            """, 
            id=elements["id"],
            name=elements["name"],
            description=elements["description"],
            link=elements["link"],
            extendedDescription=elements["extendedDescription"],
            backgroundDetails=elements["backgroundDetails"])

    @staticmethod
    def _create_cwe_status(tx, elements):
        tx.run("""
            MATCH (cwe:CWE { id:$cweId })
            MERGE (status:Status { type:$type })
            MERGE (cwe)-[:HAS_STATUS]->(status)
            """, 
            type=elements["type"],
            cweId=elements["cweId"])

    @staticmethod
    def _create_cwe_related_cwe(tx, elements):
        relation = "{}-[:{}]-{}".format("<",elements["relationship"],"" if elements["direction"]=="Left" else "",elements["relationship"],">")
        tx.run("""
            MATCH (currentCwe:CWE { id:$cweId })
            MERGE (relatedCwe:CWE { id:$relatedCweId })
            MERGE (currentCwe)""" + relation + """(relatedCwe)
            """,
            relatedCweId=elements["relatedCweId"],
            direction=elements["direction"],
            cweId=elements["cweId"])

    @staticmethod
    def _create_weakness_ordinality(tx, elements):
        tx.run("""
            MATCH (cwe:CWE { id:$cweId })
            MERGE (weaknessOrdinality:WeaknessOrdinality { type:$type, description:$description })
            MERGE (cwe)-[r:HAS_WEAKNESS_ORDINALITY]->(weaknessOrdinality)
            SET r.description = $customDescription
            """, 
            type=elements["type"],
            description=elements["description"],
            customDescription=elements["customDescription"],
            cweId=elements["cweId"])

    @staticmethod
    def _create_cwe_alternative_term(tx, elements):
        tx.run("""
            MATCH (cwe:CWE { id:$cweId })
            MERGE (alternativeTerm:AlternativeTerm { name:$name })
            SET alternativeTerm.description=$description
            MERGE (cwe)-[:HAS_ALTERNATIVE_TERM]->(alternativeTerm)
            """, 
            name=elements["name"],
            description=elements["description"],
            cweId=elements["cweId"])

    @staticmethod
    def _create_phase(tx, elements):
        tx.run("""
            MATCH (cwe:CWE { id:$cweId })
            MERGE (phase:Phase { name:$name })
            MERGE (cwe)-[r:CAN_BE_INTRODUCED_DURING]->(status)
            SET r.description=$description
            """, 
            name=elements["name"],
            description=elements["description"],
            cweId=elements["cweId"])

    @staticmethod
    def _create_security_property(tx, elements):
        tx.run("""
            MERGE (:SecurityProperty { name:$name })
            """, 
            name=elements["name"])

    @staticmethod
    def _create_impact(tx, elements):
        tx.run("""
            MERGE (:Impact { name:$name })
            """, 
            name=elements["name"])
    
    @staticmethod
    def _remove_cwe_consequences(tx, elements):
        tx.run("""
            MATCH (cwe:CWE { id:$cweId })-[:HAS_COMMON_CONSEQUENCE]->(consequence:Consequence)
            DETACH DELETE consequence
            """, 
            cweId=elements["cweId"])

    @staticmethod
    def _create_cwe_consequence(tx, elements):
        tx.run( """
            MATCH (cwe:CWE { id:$cweId })
            CREATE (consequence:Consequence)
            SET consequence.description=$description
            MERGE (cwe)-[:HAS_COMMON_CONSEQUENCE]->(consequence)
            FOREACH (sec_name in $securityProperties | 
                MERGE (sec:SecurityProperty { name:sec_name }) 
                MERGE (consequence)-[:AFFECTS_SECURITY_PROPERTY]->(sec))
            FOREACH (impact_name in $impacts | 
                MERGE (impact:Impact { name:impact_name }) 
                MERGE (consequence)-[:HAS_IMPACT]->(impact))
            """, 
            description=elements["description"],
            securityProperties=elements["securityProperties"],
            impacts=elements["impacts"],
            cweId=elements["cweId"])
            
    @staticmethod
    def _create_detection_method(tx, elements):
        tx.run("""
            MATCH (cwe:CWE { id:$cweId })
            MERGE (detectionMethod:DetectionMethod { name:$name })
            MERGE (cwe)-[r:CAN_BE_DETECTED_BY]->(detectionMethod)
            SET r += { effectiveness:$effectiveness, description:$description }
            """, 
            name=elements["name"],
            description=elements["description"],
            effectiveness=elements["effectiveness"],
            cweId=elements["cweId"])

    @staticmethod
    def _create_cwe_mitigation(tx, elements):
        tx.run("""
            MATCH (cwe:CWE { id:$cweId })
            MERGE (mitigation:Mitigation { description:$description })
            MERGE (cwe)-[r:CAN_BE_MITIGATED_BY]->(mitigation)
            SET r.effectiveness=$effectiveness
            """, 
            description=elements["description"],
            effectiveness=elements["effectiveness"],
            cweId=elements["cweId"])

        if elements["phase"]:
            tx.run("""
                MATCH (mitigation:Mitigation { description:$description })
                MERGE (phase:Phase { name:$phase })
                MERGE (mitigation)-[:DURING_PHASE]->(phase)
                """, 
                phase=elements["phase"],
                description=elements["description"])

        if elements["strategy"]:
            tx.run("""
                MATCH (mitigation:Mitigation { description:$description })
                MERGE (strategy:Strategy { name:$strategy })
                MERGE (mitigation)-[:HAVING_STRATEGY]->(strategy)
                """, 
                strategy=elements["strategy"],
                description=elements["description"])

    @staticmethod
    def _create_functional_area(tx, elements):
        tx.run("""
            MATCH (cwe:CWE { id:$cweId })
            MERGE (functionalArea:FunctionalArea { name:$name })
            MERGE (cwe)-[:MAY_OCCURS_IN_FUNCTIONAL_AREA]->(functionalArea)
            """, 
            name=elements["name"],
            cweId=elements["cweId"])

    @staticmethod
    def _create_affected_resource(tx, elements):
        tx.run("""
            MATCH (cwe:CWE { id:$cweId })
            MERGE (resource:Resource { name:$name })
            MERGE (cwe)-[:AFFECTS_RESOURCE]->(resource)
            """, 
            name=elements["name"],
            cweId=elements["cweId"])

    @staticmethod
    def _create_cwe_related_capec(tx, elements):
        tx.run("""
            MATCH (cwe:CWE { id:$cweId })
            MERGE (capec:CAPEC { id:$capecId })
            MERGE (cwe)-[:HAS_RELATED_ATTACK_PATTERN]->(capec)
            """, 
            capecId=elements["capecId"],
            cweId=elements["cweId"])


    def write_cwe(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_cwe, elements)

    def write_cwe_status(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_cwe_status, elements)

    def write_cwe_related_cwe(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_cwe_related_cwe, elements)

    def write_weakness_ordinality(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_weakness_ordinality, elements)

    def write_cwe_alternative_term(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_cwe_alternative_term, elements)

    def write_phase(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_phase, elements)

    def write_security_property(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_security_property, elements)

    def write_impact(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_impact, elements)

    def write_cwe_consequence(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_cwe_consequence, elements)

    def delete_cwe_consequences(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._remove_cwe_consequences, elements)

    def write_detection_method(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_detection_method, elements)

    def write_cwe_mitigation(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_cwe_mitigation, elements)

    def write_functional_area(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_functional_area, elements)

    def write_affected_resource(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_affected_resource, elements)

    def write_cwe_related_capec(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_cwe_related_capec, elements)

    def write_cwe_index(self):
        self.driver.execute_query("""CREATE INDEX cwe_id IF NOT EXISTS FOR (cwe:CWE) ON (cwe.id )""")
    
    def handle_cwe(self, source_filename):
        ordinality_descriptions = {
            "Primary":"Where the weakness exists independent of other weaknesses",
            "Resultant":"Where the weakness is typically related to the presence of some other weaknesses",
            "Indirect":"Where the weakness is a quality issue that might indirectly make it easier to introduce security-relevant weaknesses or make them more difficult to detect"
        }

        related_cwe_regex = re.compile("^NATURE:(.*?):CWE ID:(.*?):VIEW ID:(.*?)(?::ORDINAL:(.*))?$")
        weakness_ordinality_regex = re.compile("^ORDINALITY:(.*?)(?::DESCRIPTION:(.*))?$")
        alternative_term_regex = re.compile("^TERM:(.*?)(?::DESCRIPTION:(.*))?$")
        phase_regex = re.compile("^PHASE:(.*?)(?::NOTE:(.*))?$")
        consequence_regex = re.compile("^(?:SCOPE:(.*?))?(?::IMPACT:(.*?))?(?::NOTE:(.*))?$")
        detection_method_regex = re.compile("^METHOD:(.*?):DESCRIPTION:(.*?)(?::EFFECTIVENESS:(.*))?$")
        mitigation_regex = re.compile("^(?:PHASE:(.*?))?(?::STRATEGY:(.*?))?[:]*(?:DESCRIPTION:(.*?))?(?::EFFECTIVENESS:(.*))?$")

        # Creating the indexes for the CWE nodes
        self.write_cwe_index()
        
        cwe_count = 0
        with open(source_filename, mode='r', encoding='utf-8') as csv_file:
            csv_reader = csv.DictReader(csv_file)
            cwe_count = sum(1 for row in csv_reader) - 1

        with open(source_filename, mode='r', encoding='utf-8') as csv_file:
            csv_reader = csv.DictReader(csv_file)
            for idx,cwe in enumerate(csv_reader,1):
                self.printProgressBar(idx,cwe_count,"CWE")

                self.write_cwe({
                    "id":cwe["CWE-ID"],
                    "name":cwe["Name"],
                    "description":cwe["Description"],
                    "link":"https://cwe.mitre.org/data/definitions/{}.html".format(cwe["CWE-ID"]),
                    "extendedDescription":cwe["Extended Description"] if cwe["Extended Description"] else None,
                    "backgroundDetails":cwe["Background Details"].replace("::","") if cwe["Background Details"] else None
                })
                if cwe["Status"]:
                    self.write_cwe_status({
                        "type":cwe["Status"],
                        "cweId":cwe["CWE-ID"]
                    })
                if cwe["Related Weaknesses"]:
                    for related_cwe in [elem for elem in cwe["Related Weaknesses"].split("::") if elem]:
                        sup = related_cwe_regex.search(related_cwe)
                        if sup.group(3) == "1000":
                            self.write_cwe_related_cwe({
                                "relatedCweId":sup.group(2),
                                "relationship":self.relationship[sup.group(1)]["relationship"],
                                "direction":self.relationship[sup.group(1)]["direction"],
                                "cweId":cwe["CWE-ID"]
                            })
                if cwe["Weakness Ordinalities"]:
                    for ordinality in [elem for elem in cwe["Weakness Ordinalities"].split("::") if elem]:
                        sup = weakness_ordinality_regex.search(ordinality)
                        self.write_weakness_ordinality({
                            "type":sup.group(1),
                            "description":ordinality_descriptions[sup.group(1)],
                            "customDescription":sup.group(2),
                            "cweId":cwe["CWE-ID"]
                        })
                if cwe["Alternate Terms"]:
                    for term in [elem for elem in cwe["Alternate Terms"].split("::") if elem]:
                        sup = alternative_term_regex.search(term)
                        self.write_cwe_alternative_term({
                            "name":sup.group(1),
                            "description":sup.group(2),
                            "cweId":cwe["CWE-ID"]
                        })
                if cwe["Modes Of Introduction"]:
                    for phase in [elem for elem in cwe["Modes Of Introduction"].split("::") if elem]:
                        sup = phase_regex.search(phase)
                        self.write_phase({
                            "name":sup.group(1),
                            "description":sup.group(2),
                            "cweId":cwe["CWE-ID"]
                        })

                if cwe["Common Consequences"]:
                    # Deleting the previous "Consequence" nodes before recreating the new ones. 
                    # This is necessary cause we are using the CREATE clause
                    self.delete_cwe_consequences({
                        "cweId":cwe["CWE-ID"]
                    })
                    for consequence in [elem for elem in cwe["Common Consequences"].split("::") if elem]:
                        sup = consequence_regex.search(consequence)
                        # for security_property in sup.group(1).split(":SCOPE:"):
                        #     self.write_security_property({
                        #         "name":security_property
                        #     })
                        # for impact in sup.group(2).split(":IMPACT:"):
                        #     self.write_impact({
                        #         "name":impact
                        #     })

                        self.write_cwe_consequence({
                            "description":sup.group(3),
                            "securityProperties":sup.group(1).split(":SCOPE:") if sup.group(1) else [],
                            "impacts":sup.group(2).split(":IMPACT:") if sup.group(2) else [],
                            "cweId":cwe["CWE-ID"]
                        })

                if cwe["Detection Methods"]:
                    for detection_method in [elem for elem in cwe["Detection Methods"].split("::") if elem]:
                        sup = detection_method_regex.search(detection_method)
                        self.write_detection_method({
                            "name":sup.group(1),
                            "description":sup.group(2),
                            "effectiveness":sup.group(3),
                            "cweId":cwe["CWE-ID"]
                        })

                if cwe["Potential Mitigations"]:
                    for mitigation in [elem for elem in cwe["Potential Mitigations"].split("::") if elem]:
                        if(sup := mitigation_regex.search(mitigation)) is not None:
                            self.write_cwe_mitigation({
                                "phase":sup.group(1),
                                "strategy":sup.group(2),
                                "description":sup.group(3),
                                "effectiveness":sup.group(4),
                                "cweId":cwe["CWE-ID"]
                            })

                if cwe["Functional Areas"]:
                    for area in [elem for elem in cwe["Functional Areas"].split("::") if elem]:
                        self.write_functional_area({
                            "name":area,
                            "cweId":cwe["CWE-ID"]
                        })
                if cwe["Affected Resources"]:
                    for resource in [elem for elem in cwe["Affected Resources"].split("::") if elem]:
                        self.write_affected_resource({
                            "name":resource,
                            "cweId":cwe["CWE-ID"]
                        })
                if cwe["Related Attack Patterns"]:
                    for capec in [elem for elem in cwe["Related Attack Patterns"].split("::") if elem]:
                        self.write_cwe_related_capec({
                            "capecId":capec,
                            "cweId":cwe["CWE-ID"]
                        })

            print("")

    # ==============================================
    # =============== HANDLE CAPEC =================
    # ==============================================

    @staticmethod
    def _create_capec(tx, elements):
        tx.run("""
            MERGE (capec:CAPEC { id:$id })
            SET capec += { name:$name, description:$description, link:$link }
            """, 
            id=elements["id"],
            name=elements["name"],
            description=elements["description"],
            link=elements["link"])

    @staticmethod
    def _create_capec_status(tx, elements):
        tx.run("""
            MATCH (capec:CAPEC { id:$capecId })
            MERGE (status:Status { type:$type })
            MERGE (capec)-[:HAS_STATUS]->(status)
            """, 
            type=elements["type"],
            capecId=elements["capecId"])

    @staticmethod
    def _create_capec_alternative_term(tx, elements):
        tx.run("""
            MATCH (capec:CAPEC { id:$capecId })
            MERGE (alternativeTerm:AlternativeTerm { name:$name })
            SET alternativeTerm.description=$description
            MERGE (capec)-[:HAS_ALTERNATIVE_TERM]->(alternativeTerm)
            """, 
            name=elements["name"],
            description=elements["description"],
            capecId=elements["capecId"])

    @staticmethod
    def _create_capec_scale_level(tx, elements):
        tx.run("""
            MATCH (capec:CAPEC { id:$capecId })
            MERGE (scaleLevel:ScaleLevel { level:$level })
            MERGE (capec)-[:"""+ elements["relationship"] +"""]->(scaleLevel)
            """, 
            level=elements["level"],
            capecId=elements["capecId"])

    @staticmethod
    def _create_execution_flow(tx, elements):
        tx.run("""
            MATCH (capec:CAPEC { id:$capecId })
            MERGE (ef:ExecutionFlow:"""+ elements["additionalLabel"] +""" { description:$description })
            SET ef.title=$title
            MERGE (capec)-[r:"""+ elements["relationship"] +"""]->(ef)
            SET r.flowStepNumber=$flowStepNumber
            """, 
            title=elements["title"],
            description=elements["description"],
            flowStepNumber=elements["flowStepNumber"],
            capecId=elements["capecId"])

    @staticmethod
    def _create_technique(tx, elements):
        additionalProperties = "title:$executionFlowTitle, " if elements["executionFlowTitle"] else ""
        tx.run("""
            MATCH (ef:ExecutionFlow { """ + additionalProperties + """ description:$executionFlowDescription })
            MERGE (technique:Technique { description:$description })
            MERGE (ef)-[:HAS_TECHNIQUE]->(technique)
            """, 
            executionFlowTitle=elements["executionFlowTitle"],
            executionFlowDescription=elements["executionFlowDescription"],
            description=elements["description"])

    @staticmethod
    def _create_prerequisite(tx, elements):
        tx.run("""
            MATCH (capec:CAPEC { id:$capecId })
            MERGE (prerequisite:Prerequisite { description:$description })
            MERGE (capec)-[:HAS_PREREQUISITE]->(prerequisite)
            """, 
            description=elements["description"],
            capecId=elements["capecId"])

    @staticmethod
    def _create_skill(tx, elements):
        tx.run("""
            MATCH (capec:CAPEC { id:$capecId })
            MERGE (skill:Skill { description:$description })
            MERGE (scaleLevel:ScaleLevel { level:$level })
            MERGE (capec)-[:REQUIRES_SKILL]->(skill)-[:REQUIRES_EXPERTISE_LEVEL]->(scaleLevel)
            """, 
            description=elements["description"],
            level=elements["level"],
            capecId=elements["capecId"])

    @staticmethod
    def _create_asset(tx, elements):
        tx.run("""
            MATCH (capec:CAPEC { id:$capecId })
            MERGE (asset:Asset { description:$description })
            MERGE (capec)-[:REQUIRES_ASSET]->(asset)
            """, 
            description=elements["description"],
            capecId=elements["capecId"])

    @staticmethod
    def _create_indicator(tx, elements):
        tx.run("""
            MATCH (capec:CAPEC { id:$capecId })
            MERGE (indicator:AttackIndicator { description:$description })
            MERGE (capec)-[:HAS_ATTACK_INDICATOR]->(indicator)
            """, 
            description=elements["description"],
            capecId=elements["capecId"])

    @staticmethod
    def _remove_capec_consequences(tx, elements):
        tx.run("""
            MATCH (capec:CAPEC { id:$capecId })-[:HAS_COMMON_CONSEQUENCE]->(consequence:Consequence)
            DETACH DELETE consequence
            """, 
            capecId=elements["capecId"])

    @staticmethod
    def _create_capec_consequence(tx, elements):
        tx.run( """
            MATCH (capec:CAPEC { id:$capecId })
            CREATE (consequence:Consequence)
            SET consequence.description=$description
            MERGE (capec)-[:HAS_COMMON_CONSEQUENCE]->(consequence)
            FOREACH (sec_name in $securityProperties | 
                MERGE (sec:SecurityProperty { name:sec_name }) 
                MERGE (consequence)-[:AFFECTS_SECURITY_PROPERTY]->(sec))
            FOREACH (impact_name in $impacts | 
                MERGE (impact:Impact { name:impact_name }) 
                MERGE (consequence)-[:HAS_IMPACT]->(impact))
            """, 
            description=elements["description"],
            securityProperties=elements["securityProperties"],
            impacts=elements["impacts"],
            capecId=elements["capecId"])

    @staticmethod
    def _create_capec_mitigation(tx, elements):
        tx.run("""
            MATCH (capec:CAPEC { id:$capecId })
            MERGE (mitigation:Mitigation { description:$description })
            MERGE (capec)-[:CAN_BE_MITIGATED_BY]->(mitigation)
            """, 
            description=elements["description"],
            capecId=elements["capecId"])

    @staticmethod
    def _create_capec_example(tx, elements):
        tx.run("""
            MATCH (capec:CAPEC { id:$capecId })
            MERGE (example:Example { description:$description })
            MERGE (capec)-[:HAS_EXAMPLE]->(example)
            """, 
            description=elements["description"],
            capecId=elements["capecId"])

    @staticmethod
    def _create_capec_related_capec(tx, elements):
        relation = "{}-[:{}]-{}".format("<",elements["relationship"],"" if elements["direction"]=="Left" else "",elements["relationship"],">")
        tx.run("""
            MATCH (currentCapec:CAPEC { id:$capecId })
            MERGE (relatedCapec:CAPEC { id:$relatedCapecId })
            MERGE (currentCapec)""" + relation + """(relatedCapec)
            """,
            relatedCapecId=elements["relatedCapecId"],
            direction=elements["direction"],
            capecId=elements["capecId"])

    def write_capec(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_capec, elements)

    def write_capec_status(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_capec_status, elements)

    def write_capec_alternative_term(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_capec_alternative_term, elements)

    def write_capec_scale_level(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_capec_scale_level, elements)

    def write_execution_flow(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_execution_flow, elements)

    def write_technique(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_technique, elements)

    def write_prerequisite(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_prerequisite, elements)

    def write_skill(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_skill, elements)

    def write_asset(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_asset, elements)

    def write_indicator(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_indicator, elements)

    def delete_capec_consequences(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._remove_capec_consequences, elements)

    def write_capec_consequence(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_capec_consequence, elements)

    def write_capec_mitigation(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_capec_mitigation, elements)

    def write_capec_example(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_capec_example, elements)

    def write_capec_related_capec(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_capec_related_capec, elements)
    
    def create_capec_index(self):
        self.driver.execute_query("""
            CREATE INDEX capec_id IF NOT EXISTS FOR (capec:CAPEC) ON (capec.id)
            """)

    def handle_capec(self, source_filename):
        alternative_term_regex = re.compile("^TERM:(.*?)(?::DESCRIPTION[:]*(.*))?$")
        execution_flow_regex = re.compile("^STEP:(.*?)(?::PHASE:(.*?))?(?::DESCRIPTION:(?:\[(.*?)\] )?(.*?))?(?::TECHNIQUE:(.*))?$")
        skill_regex = re.compile("^SKILL:(.*?)(?::LEVEL:(.*))?$")
        capec_consequence_regex = re.compile("^(?:SCOPE:(.*?))?(?:TECHNICAL IMPACT:(.*?))?(?::NOTE:(.*))?$")
        related_capec_regex = re.compile("^NATURE:(.*?):CAPEC ID:(.*)$")

        # Creating the indexes for the CAPEC nodes
        self.create_capec_index()
        
        capec_count = 0
        with open(source_filename, mode='r', encoding='utf-8') as csv_file:
            csv_reader = csv.DictReader(csv_file)
            capec_count = sum(1 for row in csv_reader) - 1

        with open(source_filename, mode='r', encoding='utf-8') as csv_file:
            csv_reader = csv.DictReader(csv_file)
            for idx,capec in enumerate(csv_reader,1):
                self.printProgressBar(idx,capec_count,"CAPEC")

                self.write_capec({
                    "id":capec["'ID"],
                    "name":capec["Name"],
                    "description":capec["Description"] if capec["Description"] else None,
                    "link":"https://capec.mitre.org/data/definitions/{}.html".format(capec["'ID"])
                })
                if capec["Status"]:
                    self.write_capec_status({
                        "type":capec["Status"],
                        "capecId":capec["'ID"]
                    })
                if capec["Alternate Terms"]:
                    for term in [elem for elem in capec["Alternate Terms"].replace(":::","::").split("::") if elem]:
                        sup = alternative_term_regex.search(term)
                        self.write_capec_alternative_term({
                            "name":sup.group(1),
                            "description":sup.group(2) if sup.group(2) else None,
                            "capecId":capec["'ID"]
                        })
                if capec["Likelihood Of Attack"]:
                    self.write_capec_scale_level({
                        "level":capec["Likelihood Of Attack"],
                        "relationship":"HAS_ATTACK_LIKELIHOOD",
                        "capecId":capec["'ID"]
                    })
                if capec["Typical Severity"]:
                    self.write_capec_scale_level({
                        "level":capec["Typical Severity"],
                        "relationship":"HAS_TYPICAL_SEVERITY",
                        "capecId":capec["'ID"]
                    })
                if capec["Execution Flow"]:
                    count_step = 1
                    for flow in [elem for elem in capec["Execution Flow"].split("::") if elem]:
                        sup = execution_flow_regex.search(flow)

                        self.write_execution_flow({
                            "title":sup.group(3),
                            "description":sup.group(4),
                            "additionalLabel":sup.group(2).capitalize(),
                            "relationship":"HAS_{}_FLOW".format(sup.group(2).upper()),
                            "flowStepNumber":count_step,
                            "capecId":capec["'ID"]
                        })
                        if sup.group(5):
                            for technique in sup.group(5).split(":TECHNIQUE:"):
                                self.write_technique({
                                    "executionFlowTitle":sup.group(3),
                                    "executionFlowDescription":sup.group(4),
                                    "description":technique
                                })

                        count_step += 1

                if capec["Prerequisites"]:
                    for prerequisite in [elem for elem in capec["Prerequisites"].split("::") if elem]:
                        self.write_prerequisite({
                            "description":prerequisite,
                            "capecId":capec["'ID"]
                        })
                if capec["Skills Required"]:
                    for skill in [elem for elem in capec["Skills Required"].split("::") if elem]:
                        sup = skill_regex.search(skill)
                        if sup:
                            self.write_skill({
                                "description":sup.group(1),
                                "level":sup.group(2),
                                "capecId":capec["'ID"]
                            })
                if capec["Resources Required"]:
                    for resource in [elem for elem in capec["Resources Required"].split("::") if elem]:
                        self.write_asset({
                            "description":resource,
                            "capecId":capec["'ID"]
                        })
                if capec["Indicators"]:
                    for indicator in [elem for elem in capec["Indicators"].split("::") if elem]:
                        self.write_indicator({
                            "description":indicator,
                            "capecId":capec["'ID"]
                        })

                if capec["Consequences"]:
                    # Deleting the previous "Consequence" nodes before recreating the new ones. 
                    # This is necessary cause we are using the CREATE clause
                    self.delete_capec_consequences({
                        "capecId":capec["'ID"]
                    })
                    for consequence in [elem for elem in capec["Consequences"].split("::") if elem]:
                        # Edge case. The easiest and fastest way is to hardcoded it.
                        if capec["'ID"] == "508":
                            consequence = consequence.split(":LIKELIHOOD:")[0]
                        sup = capec_consequence_regex.search(consequence)
                        self.write_capec_consequence({
                            "description":sup.group(3),
                            "securityProperties":sup.group(1).split(":SCOPE:") if sup.group(1) else None,
                            "impacts":sup.group(2).split(":TECHNICAL IMPACT:") if sup.group(2) else None,
                            "capecId":capec["'ID"]
                        })

                if capec["Mitigations"]:
                    for mitigation in [elem for elem in capec["Mitigations"].split("::") if elem]:
                        # Even though some of the descriptions contain also the "phase" in which the mitigation might be applied, 
                        # they don't follow any previous standards (i.e. hard to select even using regexes).
                        #
                        # Example of phases: Operation, Operational, Implementation, Design, Configuration, Usage,
                        # Pre-design, Pre-design through Build, Assurance
                        self.write_capec_mitigation({
                            "description":mitigation,
                            "capecId":capec["'ID"]
                        })
                if capec["Example Instances"]:
                    for example in [elem for elem in capec["Example Instances"].split("::") if elem]:
                        self.write_capec_example({
                            "description":example,
                            "capecId":capec["'ID"]
                        })
                if capec["Related Attack Patterns"]:
                    for related_capec in [elem for elem in capec["Related Attack Patterns"].split("::") if elem]:
                        sup = related_capec_regex.search(related_capec)
                        self.write_capec_related_capec({
                            "relatedCapecId":sup.group(2),
                            "relationship":self.relationship[sup.group(1)]["relationship"],
                            "direction":self.relationship[sup.group(1)]["direction"],
                            "capecId":capec["'ID"]
                        })
                
                # No need to process the "Related Weaknesses" field (i.e. CWE) since it's already been done in the CWE part.

            print("")

    # ==============================================
    # =============== HANDLE EPSS ==================
    # ==============================================
    
    def write_epss(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_epss, elements)
    
    def clean_epss(self):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._delete_epss)
    
    @staticmethod
    def _delete_epss(tx):
        tx.run("""MATCH (epss:EPSS) DETACH DELETE epss""")
        
    
    @staticmethod
    def _create_epss(tx, elements):
        tx.run("""
               MATCH (cve:CVE { id:$cveId })
               MERGE (epss:EPSS { probability:$probability, percentile:$percentile})
               MERGE (cve)-[:HAS_EPSS]->(epss)
               """,
               cveId=elements["cveId"],
               probability=elements["probability"],
               percentile=elements["percentile"])
        
    def handle_epss(self, source_filename):
        
        #we need to first remove existing epss
        self.clean_epss()
        
        total=0
        with open(source_filename, 'r', encoding="utf-8") as file:
            reader = csv.reader(file, delimiter=',')
            for row in reader:
                total += 1
        
        total = total - 2
        
        with open(source_filename, 'r', encoding="utf-8") as file:
            reader = csv.reader(file, delimiter=',')
            # Skip the first row (comment with version and last update date)
            next(reader)
            # Read the second row (column headers)
            headers = next(reader)
            
            idx=0
            
            for row in reader:
                # Create a dictionary using the headers as keys and row values
                row_dict = dict(zip(headers, row))
                self.printProgressBar(idx,total,"EPSS")
                
                self.write_epss({
                    "cveId":row_dict["cve"],
                    "probability":float(row_dict["epss"]),
                    "percentile":float(row_dict["percentile"]),
                })
                idx += 1
                
            print("")
    
    # ==============================================
    # =============== HANDLE SOURCES ===============
    # ==============================================
    
    @staticmethod
    def _create_source_v2_acceptance_level(tx, elements):
        tx.run("""
            MATCH (cna:CNA)-[:REACHABLE_BY_EMAIL]->(:ContactInfo { contact:$cnaEmail })
            MERGE (al:V2_ACCEPTANCE_LEVEL { description:$description, lastModified:$lastModified })
            MERGE (cna)-[:HAS_V2_ACCEPTANCE_LEVEL]->(al)
            """, 
            cnaEmail=elements["email"],
            description=elements["description"],
            lastModified=elements["lastModified"])
    
    @staticmethod
    def _create_source_v3_acceptance_level(tx, elements):
        tx.run("""
            MATCH (cna:CNA)-[:REACHABLE_BY_EMAIL]->(:ContactInfo { contact:$cnaEmail })
            MERGE (al:V3_ACCEPTANCE_LEVEL { description:$description, lastModified:$lastModified })
            MERGE (cna)-[:HAS_V3_ACCEPTANCE_LEVEL]->(al)
            """, 
            cnaEmail=elements["email"],
            description=elements["description"],
            lastModified=elements["lastModified"])
    
    @staticmethod
    def _create_source_cwe_acceptance_level(tx, elements):
        tx.run("""
            MATCH (cna:CNA)-[:REACHABLE_BY_EMAIL]->(:ContactInfo { contact:$cnaEmail })
            MERGE (al:CWE_ACCEPTANCE_LEVEL { description:$description, lastModified:$lastModified })
            MERGE (cna)-[:HAS_CWE_ACCEPTANCE_LEVEL]->(al)
            """, 
            cnaEmail=elements["email"],
            description=elements["description"],
            lastModified=elements["lastModified"])
            
    def write_source_v2_acceptance_level(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_source_v2_acceptance_level, elements)
    
    def write_source_v3_acceptance_level(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_source_v3_acceptance_level, elements)
    
    def write_source_cwe_acceptance_level(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_source_cwe_acceptance_level, elements)
    
    def handle_sources(self, source_filename):
        with open(source_filename, mode='r') as file:
            data = json.load(file)
            source_count = len(data["sources"])
            for idx,source in enumerate(data["sources"],1):
                self.printProgressBar(idx,source_count,"sources")
                    
                if "v2AcceptanceLevel" in source:
                    self.write_source_v2_acceptance_level({
                        "email": source["contactEmail"],
                        "description": source["v2AcceptanceLevel"]["description"],
                        "lastModified": source["v2AcceptanceLevel"]["lastModified"]
                    })
                    
                if "v3AcceptanceLevel" in source:
                    self.write_source_v3_acceptance_level({
                        "email": source["contactEmail"],
                        "description": source["v3AcceptanceLevel"]["description"],
                        "lastModified": source["v3AcceptanceLevel"]["lastModified"]
                    })
                
                if "cweAcceptanceLevel" in source:
                    self.write_source_cwe_acceptance_level({
                        "email": source["contactEmail"],
                        "description": source["cweAcceptanceLevel"]["description"],
                        "lastModified": source["cweAcceptanceLevel"]["lastModified"]
                    })
            print("")

    # ==============================================
    # =============== HANDLE CPE ===================
    # ==============================================
    
    @staticmethod
    def _create_cpe_title(tx, elements):
        tx.run("""
            MATCH (:CVE)-[:AFFECTS { cpe23Uri:$cpeName }]->(p:Product)
            MERGE (ti:Title { title:$title, language:$language })
            MERGE (p)-[:HAS_TITLE]->(ti)
            """, 
            cpeName=elements["cpeName"],
            title=elements["title"],
            language=elements["language"])
        
    @staticmethod
    def _create_cpe_refs(tx, elements):
        tx.run("""
            MATCH (:CVE)-[:AFFECTS { cpe23Uri:$cpeName }]->(p:Product)
            MERGE (ref:Ref { ref:$ref})
            MERGE (p)-[:HAS_REF {type: $type}]->(ref)
            """, 
            cpeName=elements["cpeName"],
            ref=elements["ref"],
            type=elements["type"])
    
    def write_cpe_title(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_cpe_title, elements)
            
    def write_cpe_refs(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_cpe_refs, elements)

    def handle_cpe(self, cpe_filename):
        with open(cpe_filename, mode='r') as file:
            data = json.load(file)
            product_count = len(data["products"])
            for idx,product in enumerate(data["products"],1):
                self.printProgressBar(idx,product_count,"products")     
                cpe=product["cpe"]
                
                if not cpe["deprecated"]:
                    for title in cpe["titles"]:
                        self.write_cpe_title({
                            "cpeName": cpe["cpeName"],
                            "title": title["title"],
                            "language": title["lang"]
                        })
                    
                    
                    #TODO little fix here if ref is there or not
                    if "refs" in cpe:
                        for ref in cpe["refs"]:
                            if "type" in ref:
                                self.write_cpe_refs({
                                    "cpeName": cpe["cpeName"],
                                    "ref": ref["ref"],
                                    "type": ref["type"]
                                })
                
            print("")
    
    # ==============================================
    # =============== HANDLE CVE ===================
    # ==============================================

    @staticmethod
    def _create_cve(tx, elements):
        tx.run("""
            MERGE (cve:CVE { id:$id, publishedDate:$publishedDate, lastModifiedDate:$lastModifiedDate })
            SET cve.description=$description
            """,    
            id=elements["id"],
            description=elements["description"],
            publishedDate=elements["publishedDate"],
            lastModifiedDate=elements["lastModifiedDate"])

    @staticmethod
    def _create_cve_related_cna(tx, elements):
        tx.run("""
            MATCH (cve:CVE { id:$cveId })
            MATCH (cna:CNA)-[:REACHABLE_BY_EMAIL]->(:ContactInfo { contact:$cnaEmail })
            MERGE (cve)<-[:ASSIGNED]-(cna)
            """, 
            cnaEmail=elements["cnaEmail"],
            cveId=elements["cveId"])

    @staticmethod
    def _create_cve_related_cwe(tx, elements):
        tx.run("""
            MATCH (cve:CVE { id:$cveId })
            MERGE (cwe:CWE { id:$cweId })
            MERGE (cve)-[:HAS_WEAKNESS]->(cwe)
            """, 
            cweId=elements["cweId"],
            cveId=elements["cveId"])
        
    @staticmethod
    def _create_metric(tx, elements):
        tx.run('''
            MATCH (cve:CVE { id:$cveId })
            MERGE (metric:Metric:'''+ elements["severity"] +''' { vector:$vector, baseScore:$baseScore })
            MERGE (cve)-[:HAS_METRIC { exploitabilityScore:$exploitabilityScore, impactScore:$impactScore}]->(metric)
            ''', 
            vector=elements["vector"],
            baseScore=elements["baseScore"],
            exploitabilityScore=elements["exploitabilityScore"],
            impactScore=elements["impactScore"],
            cveId=elements["cveId"])

    @staticmethod
    def _create_reference(tx, elements):
        # MATCH (ref:Reference:''' + elements["tags"] + ''') WHERE SIZE(LABELS(ref)) = $countLabels
        tx.run("""
            MATCH (cve:CVE { id:$cveId })
            MERGE (ref { url:$url })
            MERGE (cve)-[:HAS_LINK_TO]->(ref)
            """,
            url=elements["url"],
            cveId=elements["cveId"])

    @staticmethod
    def _create_vendor_and_product(tx, elements):
        tx.run('''
            MERGE (vnd:Vendor { name:$vendorName } )
            MERGE (prd:Product { name:$productName, type:$productType } )
            MERGE (vnd)-[:OWN]->(prd)
            ''',
            vendorName=elements["vendorName"],
            productName=elements["productName"],
            productType=elements["productType"])

    @staticmethod
    def _create_version(tx, elements):
        tx.run('''
            MATCH (cve:CVE { id:$cveId })
            MATCH (prd:Product { name:$productName } )
            MERGE (cve)-[aff:AFFECTS { vulnerable:$vulnerable, versionStartIncluding:$versionStartIncluding, cpe23Uri:$cpe23Uri } ]->(prd)
            SET aff.versionEndExcluding=$versionEndExcluding
            ''',
            cveId=elements["cveId"],
            productName=elements["productName"],
            vulnerable=elements["vulnerable"],
            cpe23Uri=elements["cpe23Uri"],
            versionStartIncluding=elements["versionStartIncluding"],
            versionEndExcluding=elements["versionEndExcluding"])
                       
    def write_cve(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_cve, elements)

    def write_cve_related_cna(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_cve_related_cna, elements)

    def write_cve_related_cwe(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_cve_related_cwe, elements)
    
    def write_metric(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_metric, elements)

    def write_reference(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_reference, elements)

    def write_vendor_and_product(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_vendor_and_product, elements)

    def write_version(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_version, elements)
            
    def create_cve_index(self):
        self.driver.execute_query("""
            CREATE TEXT INDEX cve_id IF NOT EXISTS FOR (cve:CVE) ON (cve.id)
            """)

    def handle_cve(self, source_filename):
        with open(source_filename, mode="r", encoding='utf-8') as file:
            
            self.create_cve_index()
            
            data = json.load(file)
            cve_count = len(data["vulnerabilities"])
            for idx,cve in enumerate(data["vulnerabilities"],1):
                self.printProgressBar(idx,cve_count,"CVE")

                self.write_cve({
                    "id":cve["cve"]["id"],
                    "description":cve["cve"]["descriptions"][0]["value"],
                    "publishedDate":cve["cve"]["published"],
                    "lastModifiedDate":cve["cve"]["lastModified"],
                })
                # Before run it be sure to have run "handle_cna" first!
                self.write_cve_related_cna({
                    "cnaEmail":cve["cve"]["sourceIdentifier"],
                    "cveId":cve["cve"]["id"]
                })
                # If there are no CWE related the "description" array is empty, so no additional check needed.
                if "weaknesses" in cve["cve"]:
                    for cwe in cve["cve"]["weaknesses"]:
                        self.write_cve_related_cwe({
                            "cweId":cwe["description"][0]["value"].replace("CWE-",""),
                            "cveId":cve["cve"]["id"]
                        })
                    
                if "cvssMetricV30" in cve["cve"]["metrics"]:
                    self.write_metric({
                        "vector":cve["cve"]["metrics"]["cvssMetricV30"][0]["cvssData"]["vectorString"].replace("CVSS:3.0/",""),
                        "baseScore":cve["cve"]["metrics"]["cvssMetricV30"][0]["cvssData"]["baseScore"],
                        "severity":cve["cve"]["metrics"]["cvssMetricV30"][0]["cvssData"]["baseSeverity"].capitalize(),
                        "exploitabilityScore":cve["cve"]["metrics"]["cvssMetricV30"][0]["exploitabilityScore"],
                        "impactScore":cve["cve"]["metrics"]["cvssMetricV30"][0]["impactScore"],
                        "cveId":cve["cve"]["id"]
                    })
                if "cvssMetricV31" in cve["cve"]["metrics"]:
                    self.write_metric({
                        "vector":cve["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["vectorString"].replace("CVSS:3.1/",""),
                        "baseScore":cve["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"],
                        "severity":cve["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseSeverity"].capitalize(),
                        "exploitabilityScore":cve["cve"]["metrics"]["cvssMetricV31"][0]["exploitabilityScore"],
                        "impactScore":cve["cve"]["metrics"]["cvssMetricV31"][0]["impactScore"],
                        "cveId":cve["cve"]["id"]
                    })
                    
                if "references" in cve["cve"]:
                    for ref in cve["cve"]["references"]:
                        if "tags" in ref:
                            additionalLabels = ":Ref".join(map(lambda tag: tag.title(),ref["tags"])).replace(" ","").replace("/","").replace("\\","").replace("|","").replace("-","")
                            additionalLabels = additionalLabels if not additionalLabels else ":" + additionalLabels
                        else:
                            additionalLabels = ""
                        self.write_reference({
                            "labels":":Reference" + additionalLabels,
                            "url":ref["url"],
                            "cveId":cve["cve"]["id"]
                        })
                # TODO - Possible integration with https://nvd.nist.gov/developers/products
                #Be sure to have run "handle_cpe" first!
                if("configurations" in cve["cve"]):
                    for configuration in cve["cve"]["configurations"]:
                        for node in configuration["nodes"]:
                            lastProduct = None
                            lastVendor = None
                            for cpe in node["cpeMatch"]:
                                
                                cpe_elements = cpe["criteria"].split(":")

                                if(lastProduct is None or lastProduct != cpe_elements[4] or 
                                   lastVendor is None or lastVendor != cpe_elements[3]):
                                    lastProduct = cpe_elements[4]
                                    lastVendor = cpe_elements[3]
                                
                                    self.write_vendor_and_product({
                                        "vendorName":cpe_elements[3],
                                        "productName":cpe_elements[4],
                                        "productType":("Application" if cpe_elements[2]=="a" else "Hardware" if cpe_elements[2]=="h" else "Operating Systems")
                                    })

                                # TODO - At the moment the graph doesn't model the combination AND/OR of products
                                # (es. CVE-2019-5163, CVE-2021-43803) or CVE-2017-20026 (where there's no "versionStartIncluding")
                                if "versionStartIncluding" in cpe:
                                    self.write_version({
                                        "cveId":cve["cve"]["id"],
                                        "productName":cpe_elements[4],
                                        "vulnerable":cpe["vulnerable"],
                                        "cpe23Uri":cpe["criteria"],
                                        "versionStartIncluding":cpe["versionStartIncluding"],
                                        "versionEndExcluding":cpe["versionEndExcluding"] if "versionEndExcluding" in cpe else None
                                    })

            print("")

    # ==============================================
    # =============== HANDLE MITRE ===================
    # ==============================================
    
    @staticmethod
    def _create_tactic(tx, elements):
        tx.run("""
            MERGE (tactic:TACTIC { id:$id, name:$name, description:$description, link:$link })
            """, 
            id=elements["external_id"],
            name=elements["name"],
            description=elements["description"],
            link=elements["link"])

    @staticmethod
    def _create_mitre_technique(tx, elements):
        tx.run("""
            MATCH (tactic:TACTIC { id:$tacId })
            MERGE (tec:AdversaryTechnique { id:$id, name:$name, description:$description, link:$link})
            MERGE (tactic)-[:HAS_MITRE_TECHNIQUE]->(tec)
            """, 
            tacId=elements["tac_external_id"],
            id=elements["external_id"],
            name=elements["name"],
            description=elements["description"],
            link=elements["link"])

    def write_tactic(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_tactic, elements)

    def write_mitre_technique(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_mitre_technique, elements)

    # ==============================================
    # =============== HANDLE GROUPS ===================
    # ==============================================

    
    @staticmethod
    def _create_GROUP(tx, elements):
        tx.run("MERGE (x:THREAT_ACTOR { name:$name, description:$description, link:$link })", 
            name=elements["name"],
            description=elements["description"],
            link=elements["link"])

    @staticmethod
    def _create_alias(tx, elements):
        tx.run("""
                MATCH (x:THREAT_ACTOR { name:$name })
                MERGE (y:THREAT_ACTOR_ALIAS { name:$alias})
                MERGE (x)-[:HAS_ALIAS]->(y)
                """,
                name = elements["name"],
                alias=elements["alias"])

    @staticmethod
    def _create_group_with_technique(tx, elements):
        tx.run("""
                MATCH (x:AdversaryTechnique { id:$id })
                MERGE (y:THREAT_ACTOR { name:$name, description:$description, link:$link})
                MERGE (x)-[:IS_USED_BY]->(y)
                """,
                id = elements["tecId"],
                name = elements["name"],
                description = elements["description"],
                link = elements["link"])
              
    def write_group(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_GROUP, elements)

    def write_alias(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_alias, elements)

    def write_group_with_technique(self, elements):
        with self.driver.session(database=self.db) as session:
            res = session.execute_write(self._create_group_with_technique, elements)
    
    def handle_group(self, json):
        self.write_group({
            "name":json.get('name'),
            "description":json.get("description"),
            "link":json.get("link")
        })
        for item in json.get('aliases'):
            self.write_alias({
                'name':json.get('name'),
                'alias':item
            })
    
    def first_mitre_run(self, json):
        mitre_attack_data = MitreAttackData("enterprise-attack.json")
        techniques = []
        tactics = mitre_attack_data.get_tactics(remove_revoked_deprecated=True)
        tactics_new = []
        for item in tactics:
            for item2 in item.get('external_references'):
                if item2.get('source_name') == "mitre-attack":
                    tactics_new.append({
                        'external_id':item2.get('external_id'),
                        'name':item.get('name'),
                        'description':item.get('description'),
                        'link':item2.get('url'),
                        "short-name":item.get('x_mitre_shortname'),
                        'techniques':[]
                    })
        for tactic in tactics_new:
            techniques = mitre_attack_data.get_techniques_by_tactic(tactics_new[0].get('short-name'), "enterprise-attack", remove_revoked_deprecated=True)
            for tec in techniques:
                for tec2 in tec.get('external_references'):
                    if tec2.get('source_name') == "mitre-attack":
                        tactic.get('techniques').append({
                            'external_id':tec2.get('external_id'),
                            'name':tec.get('name'),
                            'description':tec.get('description'),
                            'link':tec2.get('url'),
                        })
        for tac in tactics_new:
            self.write_tactic({
                'external_id':tac.get('external_id'),
                'name':tac.get('name'),
                'description':tac.get('description'),
                'link':tac.get('link')
            }) 
            for tec in tac.get('techniques'):
                self.write_mitre_technique({
                    'tac_external_id':tac.get('external_id'),
                    'external_id':tec.get('external_id'),
                    'name':tec.get('name'),
                    'description':tec.get('description'),
                    'link':tec.get('link')
            })
        gg = mitre_attack_data.get_all_groups_using_all_techniques()
        for id, groups in gg.items():
            attack_id = mitre_attack_data.get_attack_id(id)
            for gg in groups:
                for ex in gg.get('object').get('external_references'):
                    if ex.get('source_name') == "mitre-attack":
                        cyberGraph.write_group_with_technique({
                            "name":gg.get('object').get('name'),
                            "description":gg.get('object').get('description'),
                            "link":ex.get('url'),
                            "tecId":attack_id,
                    })
            print(f"* {attack_id} - used by {len(groups)} {'group' if len(groups) == 1 else 'groups'}")
        groups = mitre_attack_data.get_groups(remove_revoked_deprecated=True)
        print("** Analysis ended**")

if __name__ == "__main__":
    load_dotenv()

    neo4j_uri = os.getenv('NEO4J_URI')
    neo4j_username = os.getenv('NEO4J_USERNAME')
    neo4j_password = os.getenv('NEO4J_PASSWORD')

    cyberGraph = CyberGraph(neo4j_uri, neo4j_username, neo4j_password)

    cyberGraph.handle_cna("cna.json")
    cyberGraph.handle_cwe("cwe.csv")
    cyberGraph.handle_capec("capec.csv")
    cyberGraph.handle_cve("dump.json")
    cyberGraph.handle_epss("epss.csv")
    cyberGraph.first_mitre_run("enterprise-attack.json")
    #cyberGraph.handle_sources("sources.json")
    #cyberGraph.handle_cpe("cpe.json")

    cyberGraph.close()
    