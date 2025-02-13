<?php

namespace Database\Seeders;

use App\Models\Vulnerability;
use Carbon\Carbon;
use Illuminate\Database\Seeder;

class OWASPTop10Seeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        $vulnerabilities = [
            [
                'code' => 'A01:2021',
                'title' => 'Broken Access Control',
                'description' => 'Access control enforces policy such that users cannot act outside of their intended permissions. Moving up from the fifth position, 94% of applications were tested for some form of broken access control with the average incidence rate of 3.81%, and has the most occurrences in applications with over 318k.',
                'cwes' => json_encode([
                    [
                        'code' => 'CWE-200',
                        'name' => 'Exposure of Sensitive Information to an Unauthorized Actor',
                        'link' => 'https://cwe.mitre.org/data/definitions/200.html',
                    ],
                    [
                        'code' => 'CWE-201',
                        'name' => 'Exposure of Sensitive Information Through Sent Data',
                        'link' => 'https://cwe.mitre.org/data/definitions/201.html',
                    ],
                    [
                        'code' => 'CWE-285',
                        'name' => 'Improper Authorization',
                        'link' => 'https://cwe.mitre.org/data/definitions/285.html',
                    ],
                    [
                        'code' => 'CWE-306',
                        'name' => 'Missing Authentication for Critical Function',
                        'link' => 'https://cwe.mitre.org/data/definitions/306.html',
                    ],
                    [
                        'code' => 'CWE-522',
                        'name' => 'Insufficiently Protected Credentials',
                        'link' => 'https://cwe.mitre.org/data/definitions/522.html',
                    ],
                    [
                        'code' => 'CWE-601',
                        'name' => 'URL Redirection to Untrusted Site',
                        'link' => 'https://cwe.mitre.org/data/definitions/601.html',
                    ],
                    [
                        'code' => 'CWE-639',
                        'name' => 'Authorization Bypass Through User-Controlled Key',
                        'link' => 'https://cwe.mitre.org/data/definitions/639.html',
                    ],
                    [
                        'code' => 'CWE-918',
                        'name' => 'Server-Side Request Forgery (SSRF)',
                        'link' => 'https://cwe.mitre.org/data/definitions/918.html',
                    ],
                ]),
                'references' => json_encode([
                    [
                        'title' => 'OWASP Top 10:2021 - A01 Broken Access Control',
                        'link' => 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
                    ],
                    [
                        'title' => 'OWASP Access Control Cheat Sheet',
                        'link' => 'https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html',
                    ],
                    [
                        'title' => 'OWASP Proactive Controls: Enforce Access Controls',
                        'link' => 'https://owasp.org/www-project-proactive-controls/v3/en/c7-enforce-access-controls',
                    ],
                    [
                        'title' => 'OWASP Application Security Verification Standard: V4 Access Control',
                        'link' => 'https://owasp.org/www-project-application-security-verification-standard',
                    ],
                    [
                        'title' => 'OWASP Testing Guide: Access Control Testing',
                        'link' => 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README',
                    ],
                    [
                        'title' => 'OWASP Cheat Sheet: Authorization',
                        'link' => 'https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html',
                    ],
                ]),
                'created_at' => Carbon::now(),
                'updated_at' => Carbon::now(),
            ],
            [
                'code' => 'A02:2021',
                'title' => 'Cryptographic Failures',
                'description' => 'Shifting up one position to #2, previously known as Sensitive Data Exposure, which was broad symptom rather than a root cause, the focus is on failures related to cryptography which often leads to sensitive data exposure or system compromise. Notable CWE entries included are CWE-259: Use of Hard-coded Password, CWE-327: Broken or Risky Crypto Algorithm, and CWE-331 Insufficient Entropy.',
                'cwes' => json_encode([
                    [
                        'code' => 'CWE-259',
                        'name' => 'Use of Hard-coded Password',
                        'link' => 'https://cwe.mitre.org/data/definitions/259.html',
                    ],
                    [
                        'code' => 'CWE-327',
                        'name' => 'Broken or Risky Crypto Algorithm',
                        'link' => 'https://cwe.mitre.org/data/definitions/327.html',
                    ],
                    [
                        'code' => 'CWE-331',
                        'name' => 'Insufficient Entropy',
                        'link' => 'https://cwe.mitre.org/data/definitions/331.html',
                    ],
                    [
                        'code' => 'CWE-321',
                        'name' => 'Use of Hard-coded Cryptographic Key',
                        'link' => 'https://cwe.mitre.org/data/definitions/321.html',
                    ],
                    [
                        'code' => 'CWE-326',
                        'name' => 'Inadequate Encryption Strength',
                        'link' => 'https://cwe.mitre.org/data/definitions/326.html',
                    ],
                    [
                        'code' => 'CWE-358',
                        'name' => 'Improperly Implemented Security Check for Standard',
                        'link' => 'https://cwe.mitre.org/data/definitions/358.html',
                    ],
                ]),
                'references' => json_encode([
                    [
                        'title' => 'OWASP Top 10:2021 - A02 Cryptographic Failures',
                        'link' => 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
                    ],
                    [
                        'title' => 'OWASP Application Security Verification Standard (V7, 9, 10)',
                        'link' => 'https://owasp.org/www-project-application-security-verification-standard',
                    ],
                    [
                        'title' => 'OWASP Cheat Sheet: Transport Layer Protection',
                        'link' => 'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html',
                    ],
                    [
                        'title' => 'OWASP Cheat Sheet: User Privacy Protection',
                        'link' => 'https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html',
                    ],
                    [
                        'title' => 'OWASP Cheat Sheet: Password and Cryptographic Storage',
                        'link' => 'https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html',
                    ],
                    [
                        'title' => 'OWASP Testing Guide: Testing for Weak Transport Layer Security',
                        'link' => 'https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security',
                    ],
                ]),
                'created_at' => Carbon::now(),
                'updated_at' => Carbon::now(),
            ],
            [
                'code' => 'A03:2021',
                'title' => 'Injection',
                'description' => 'Moving down to the third position, 94% of the applications were tested for some form of injection with a max incidence rate of 19%, an average incidence rate of 3%, and 274k occurrences. Notable Common Weakness Enumerations (CWEs) included are CWE-79: Cross-site Scripting, CWE-89: SQL Injection, and CWE-73: External Control of File Name or Path.',
                'cwes' => json_encode([
                    [
                        'code' => 'CWE-79',
                        'name' => 'Cross-site Scripting',
                        'link' => 'https://cwe.mitre.org/data/definitions/79.html',
                    ],
                    [
                        'code' => 'CWE-89',
                        'name' => 'SQL Injection',
                        'link' => 'https://cwe.mitre.org/data/definitions/89.html',
                    ],
                    [
                        'code' => 'CWE-73',
                        'name' => 'External Control of File Name or Path',
                        'link' => 'https://cwe.mitre.org/data/definitions/73.html',
                    ],
                    [
                        'code' => 'CWE-78',
                        'name' => 'OS Command Injection',
                        'link' => 'https://cwe.mitre.org/data/definitions/78.html',
                    ],
                    [
                        'code' => 'CWE-91',
                        'name' => 'XML Injection (aka Blind XPath Injection)',
                        'link' => 'https://cwe.mitre.org/data/definitions/91.html',
                    ],
                    [
                        'code' => 'CWE-564',
                        'name' => 'SQL Injection: Hibernate',
                        'link' => 'https://cwe.mitre.org/data/definitions/564.html',
                    ],
                    [
                        'code' => 'CWE-917',
                        'name' => 'Expression Language Injection',
                        'link' => 'https://cwe.mitre.org/data/definitions/917.html',
                    ],
                ]),
                'references' => json_encode([
                    [
                        'title' => 'OWASP Top 10:2021 - A03 Injection',
                        'link' => 'https://owasp.org/Top10/A03_2021-Injection/',
                    ],
                    [
                        'title' => 'OWASP Cheat Sheet: Injection Prevention',
                        'link' => 'https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html',
                    ],
                    [
                        'title' => 'OWASP Cheat Sheet: SQL Injection Prevention',
                        'link' => 'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
                    ],
                    [
                        'title' => 'OWASP Cheat Sheet: XSS Prevention',
                        'link' => 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
                    ],
                    [
                        'title' => 'OWASP Proactive Controls: C5 Validate All Inputs',
                        'link' => 'https://owasp.org/www-project-proactive-controls/v3/en/c5-validate-inputs',
                    ],
                    [
                        'title' => 'OWASP Testing Guide: Testing for Injection',
                        'link' => 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/README',
                    ],
                ]),
                'created_at' => Carbon::now(),
                'updated_at' => Carbon::now(),
            ],
            [
                'code' => 'A04:2021',
                'title' => 'Insecure Design',
                'description' => 'A new category for 2021 focuses on risks related to design and architectural flaws, with a call for more use of threat modeling, secure design patterns, and reference architectures. As a community we need to move beyond "shift-left" in the coding space to pre-code activities that are critical for the principles of Secure by Design.',
                'cwes' => json_encode([
                    [
                        'code' => 'CWE-73',
                        'name' => 'External Control of File Name or Path',
                        'link' => 'https://cwe.mitre.org/data/definitions/73.html',
                    ],
                    [
                        'code' => 'CWE-183',
                        'name' => 'Permissive List of Allowed Inputs',
                        'link' => 'https://cwe.mitre.org/data/definitions/183.html',
                    ],
                    [
                        'code' => 'CWE-209',
                        'name' => 'Generation of Error Message Containing Sensitive Information',
                        'link' => 'https://cwe.mitre.org/data/definitions/209.html',
                    ],
                    [
                        'code' => 'CWE-256',
                        'name' => 'Unprotected Storage of Credentials',
                        'link' => 'https://cwe.mitre.org/data/definitions/256.html',
                    ],
                    [
                        'code' => 'CWE-501',
                        'name' => 'Trust Boundary Violation',
                        'link' => 'https://cwe.mitre.org/data/definitions/501.html',
                    ],
                    [
                        'code' => 'CWE-522',
                        'name' => 'Insufficiently Protected Credentials',
                        'link' => 'https://cwe.mitre.org/data/definitions/522.html',
                    ],
                ]),
                'references' => json_encode([
                    [
                        'title' => 'OWASP Top 10:2021 - A04 Insecure Design',
                        'link' => 'https://owasp.org/Top10/A04_2021-Insecure_Design/',
                    ],
                    [
                        'title' => 'OWASP Software Assurance Maturity Model (SAMM)',
                        'link' => 'https://owaspsamm.org/',
                    ],
                    [
                        'title' => 'OWASP Application Security Verification Standard (ASVS)',
                        'link' => 'https://owasp.org/www-project-application-security-verification-standard/',
                    ],
                    [
                        'title' => 'OWASP Cheat Sheet: Secure Product Design',
                        'link' => 'https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html',
                    ],
                    [
                        'title' => 'OWASP Security Requirements Cheat Sheet',
                        'link' => 'https://cheatsheetseries.owasp.org/cheatsheets/Security_Requirements_Cheat_Sheet.html',
                    ],
                    [
                        'title' => 'OWASP Threat Modeling Cheat Sheet',
                        'link' => 'https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html',
                    ],
                ]),
                'created_at' => Carbon::now(),
                'updated_at' => Carbon::now(),
            ],
            [
                'code' => 'A05:2021',
                'title' => 'Security Misconfiguration',
                'description' => '90% of applications were tested for some form of misconfiguration, with an average incidence rate of 4.5%, and over 208k occurrences of Common Weakness Enumeration (CWE) in this risk category. With more shifts into highly configurable software, it\'s not surprising to see this category move up from #6 in the previous edition. Notable CWEs included are CWE-16 Configuration and CWE-611 Improper Restriction of XML External Entity Reference.',
                'cwes' => json_encode([
                    [
                        'code' => 'CWE-16',
                        'name' => 'Configuration',
                        'link' => 'https://cwe.mitre.org/data/definitions/16.html',
                    ],
                    [
                        'code' => 'CWE-611',
                        'name' => 'Improper Restriction of XML External Entity Reference',
                        'link' => 'https://cwe.mitre.org/data/definitions/611.html',
                    ],
                    [
                        'code' => 'CWE-209',
                        'name' => 'Generation of Error Message Containing Sensitive Information',
                        'link' => 'https://cwe.mitre.org/data/definitions/209.html',
                    ],
                    [
                        'code' => 'CWE-548',
                        'name' => 'Exposure of Information Through Directory Listing',
                        'link' => 'https://cwe.mitre.org/data/definitions/548.html',
                    ],
                    [
                        'code' => 'CWE-732',
                        'name' => 'Incorrect Permission Assignment for Critical Resource',
                        'link' => 'https://cwe.mitre.org/data/definitions/732.html',
                    ],
                ]),
                'references' => json_encode([
                    [
                        'title' => 'OWASP Top 10:2021 - A05 Security Misconfiguration',
                        'link' => 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
                    ],
                    [
                        'title' => 'OWASP Cheat Sheet: Security Configuration Guide',
                        'link' => 'https://cheatsheetseries.owasp.org/cheatsheets/Configuration_and_Deployment_Management_Cheat_Sheet.html',
                    ],
                    [
                        'title' => 'OWASP Application Security Verification Standard 4.0 (Configuration)',
                        'link' => 'https://github.com/OWASP/ASVS/blob/master/4.0/en/0x10-V1-Architecture.md',
                    ],
                    [
                        'title' => 'OWASP Testing Guide: Configuration and Deployment Management Testing',
                        'link' => 'https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/README',
                    ],
                    [
                        'title' => 'OWASP Docker Top 10',
                        'link' => 'https://owasp.org/www-project-docker-top-10/',
                    ],
                    [
                        'title' => 'OWASP Kubernetes Top 10',
                        'link' => 'https://owasp.org/www-project-kubernetes-top-ten/',
                    ],
                ]),
                'created_at' => Carbon::now(),
                'updated_at' => Carbon::now(),
            ],
            [
                'code' => 'A06:2021',
                'title' => 'Vulnerable and Outdated Components',
                'description' => 'This category moves up from #9 in 2017 and is still an issue that we struggle to test and assess risk. It is the only category not to have any Common Vulnerability and Exposures (CVEs) mapped to the included CWEs, which results in significant undercounting in the data. Default configurations of vulnerability scanning tools and sample programs focus on detecting known vulnerable components but organizations need to focus on cataloging all components they use and continuously monitor sources for security issues.',
                'cwes' => json_encode([
                    [
                        'code' => 'CWE-1104',
                        'name' => 'Use of Unmaintained Third Party Components',
                        'link' => 'https://cwe.mitre.org/data/definitions/1104.html',
                    ],
                    [
                        'code' => 'CWE-937',
                        'name' => 'Using Components with Known Vulnerabilities',
                        'link' => 'https://cwe.mitre.org/data/definitions/937.html',
                    ],
                    [
                        'code' => 'CWE-1035',
                        'name' => 'OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities',
                        'link' => 'https://cwe.mitre.org/data/definitions/1035.html',
                    ],
                    [
                        'code' => 'CWE-1026',
                        'name' => 'Weaknesses in OWASP Top Ten (2017)',
                        'link' => 'https://cwe.mitre.org/data/definitions/1026.html',
                    ],
                ]),
                'references' => json_encode([
                    [
                        'title' => 'OWASP Top 10:2021 - A06 Vulnerable and Outdated Components',
                        'link' => 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/',
                    ],
                    [
                        'title' => 'OWASP Dependency Check',
                        'link' => 'https://owasp.org/www-project-dependency-check/',
                    ],
                    [
                        'title' => 'OWASP Dependency Track',
                        'link' => 'https://owasp.org/www-project-dependency-track/',
                    ],
                    [
                        'title' => 'OWASP Software Component Verification Standard',
                        'link' => 'https://owasp.org/www-project-software-component-verification-standard/',
                    ],
                    [
                        'title' => 'OWASP CycloneDX',
                        'link' => 'https://owasp.org/www-project-cyclonedx/',
                    ],
                    [
                        'title' => 'The State of Open Source Security 2020',
                        'link' => 'https://snyk.io/opensourcesecurity-2020/',
                    ],
                ]),
                'created_at' => Carbon::now(),
                'updated_at' => Carbon::now(),
            ],
            [
                'code' => 'A07:2021',
                'title' => 'Identification and Authentication Failures',
                'description' => 'Previously known as "Broken Authentication," this category slips down from the second position and now includes Common Weakness Enumerations (CWEs) related to identification failures. Notable CWEs included are CWE-297: Improper Validation of Certificate with Host Mismatch, CWE-287: Improper Authentication, and CWE-384: Session Fixation.',
                'cwes' => json_encode([
                    [
                        'code' => 'CWE-297',
                        'name' => 'Improper Validation of Certificate with Host Mismatch',
                        'link' => 'https://cwe.mitre.org/data/definitions/297.html',
                    ],
                    [
                        'code' => 'CWE-287',
                        'name' => 'Improper Authentication',
                        'link' => 'https://cwe.mitre.org/data/definitions/287.html',
                    ],
                    [
                        'code' => 'CWE-384',
                        'name' => 'Session Fixation',
                        'link' => 'https://cwe.mitre.org/data/definitions/384.html',
                    ],
                    [
                        'code' => 'CWE-639',
                        'name' => 'Authorization Bypass Through User-Controlled Key',
                        'link' => 'https://cwe.mitre.org/data/definitions/639.html',
                    ],
                    [
                        'code' => 'CWE-798',
                        'name' => 'Use of Hard-coded Credentials',
                        'link' => 'https://cwe.mitre.org/data/definitions/798.html',
                    ],
                    [
                        'code' => 'CWE-940',
                        'name' => 'Improper Verification of Source of a Communication Channel',
                        'link' => 'https://cwe.mitre.org/data/definitions/940.html',
                    ],
                ]),
                'references' => json_encode([
                    [
                        'title' => 'OWASP Top 10:2021 - A07 Identification and Authentication Failures',
                        'link' => 'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/',
                    ],
                    [
                        'title' => 'OWASP Cheat Sheet: Authentication',
                        'link' => 'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html',
                    ],
                    [
                        'title' => 'OWASP Cheat Sheet: Credential Stuffing Prevention',
                        'link' => 'https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html',
                    ],
                    [
                        'title' => 'OWASP Cheat Sheet: Forgot Password',
                        'link' => 'https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html',
                    ],
                    [
                        'title' => 'OWASP Proactive Controls: C6 Implement Digital Identity',
                        'link' => 'https://owasp.org/www-project-proactive-controls/v3/en/c6-digital-identity',
                    ],
                    [
                        'title' => 'OWASP Application Security Verification Standard: V2 Authentication',
                        'link' => 'https://owasp.org/www-project-application-security-verification-standard',
                    ],
                ]),
                'created_at' => Carbon::now(),
                'updated_at' => Carbon::now(),
            ],
            [
                'code' => 'A08:2021',
                'title' => 'Software and Data Integrity Failures',
                'description' => 'A new category for 2021 focuses on making assumptions related to software updates, critical data, and CI/CD pipelines without verifying integrity. One of the highest weighted impacts from Common Vulnerability and Exposures/Common Vulnerability Scoring System (CVE/CVSS) data. Notable Common Weakness Enumerations (CWEs) include CWE-829: Inclusion of Functionality from Untrusted Control Sphere and CWE-494: Download of Code Without Integrity Check.',
                'cwes' => json_encode([
                    [
                        'code' => 'CWE-829',
                        'name' => 'Inclusion of Functionality from Untrusted Control Sphere',
                        'link' => 'https://cwe.mitre.org/data/definitions/829.html',
                    ],
                    [
                        'code' => 'CWE-494',
                        'name' => 'Download of Code Without Integrity Check',
                        'link' => 'https://cwe.mitre.org/data/definitions/494.html',
                    ],
                    [
                        'code' => 'CWE-502',
                        'name' => 'Deserialization of Untrusted Data',
                        'link' => 'https://cwe.mitre.org/data/definitions/502.html',
                    ],
                    [
                        'code' => 'CWE-345',
                        'name' => 'Insufficient Verification of Data Authenticity',
                        'link' => 'https://cwe.mitre.org/data/definitions/345.html',
                    ],
                    [
                        'code' => 'CWE-915',
                        'name' => 'Improperly Controlled Modification of Dynamically-Determined Object Attributes',
                        'link' => 'https://cwe.mitre.org/data/definitions/915.html',
                    ],
                ]),
                'references' => json_encode([
                    [
                        'title' => 'OWASP Top 10:2021 - A08 Software and Data Integrity Failures',
                        'link' => 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/',
                    ],
                    [
                        'title' => 'OWASP Cheat Sheet: Software Supply Chain Security',
                        'link' => 'https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html',
                    ],
                    [
                        'title' => 'OWASP Cheat Sheet: Secure Build and Deployment',
                        'link' => 'https://cheatsheetseries.owasp.org/cheatsheets/Secure_Build_and_Deployment_Cheat_Sheet.html',
                    ],
                    [
                        'title' => 'OWASP Application Security Verification Standard 4.0: V14 Configuration',
                        'link' => 'https://github.com/OWASP/ASVS/blob/master/4.0/en/0x22-V14-Configuration.md',
                    ],
                    [
                        'title' => 'OWASP Source Code Analysis Tools',
                        'link' => 'https://owasp.org/www-community/Source_Code_Analysis_Tools',
                    ],
                    [
                        'title' => 'OWASP Software Composition Analysis Tools',
                        'link' => 'https://owasp.org/www-community/Source_Code_Analysis_Tools#software-composition-analysis-sca',
                    ],
                ]),
                'created_at' => Carbon::now(),
                'updated_at' => Carbon::now(),
            ],
            [
                'code' => 'A09:2021',
                'title' => 'Security Logging and Monitoring Failures',
                'description' => 'Coming in at #9, this category is to help detect, escalate, and respond to active breaches. Without logging and monitoring, breaches cannot be detected. Insufficient logging, detection, monitoring, and active response occurs any time: Auditable events are not logged, Warnings and errors generate no, inadequate, or unclear log messages, Logs of applications and APIs are not monitored for suspicious activity, Logs are only stored locally.',
                'cwes' => json_encode([
                    [
                        'code' => 'CWE-778',
                        'name' => 'Insufficient Logging',
                        'link' => 'https://cwe.mitre.org/data/definitions/778.html',
                    ],
                    [
                        'code' => 'CWE-117',
                        'name' => 'Improper Output Neutralization for Logs',
                        'link' => 'https://cwe.mitre.org/data/definitions/117.html',
                    ],
                    [
                        'code' => 'CWE-223',
                        'name' => 'Omission of Security-relevant Information',
                        'link' => 'https://cwe.mitre.org/data/definitions/223.html',
                    ],
                    [
                        'code' => 'CWE-532',
                        'name' => 'Insertion of Sensitive Information into Log File',
                        'link' => 'https://cwe.mitre.org/data/definitions/532.html',
                    ],
                    [
                        'code' => 'CWE-779',
                        'name' => 'Logging of Excessive Data',
                        'link' => 'https://cwe.mitre.org/data/definitions/779.html',
                    ],
                ]),
                'references' => json_encode([
                    [
                        'title' => 'OWASP Top 10:2021 - A09 Security Logging and Monitoring Failures',
                        'link' => 'https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/',
                    ],
                    [
                        'title' => 'OWASP Cheat Sheet: Logging',
                        'link' => 'https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html',
                    ],
                    [
                        'title' => 'OWASP Proactive Controls: C9 Implement Security Logging and Monitoring',
                        'link' => 'https://owasp.org/www-project-proactive-controls/v3/en/c9-security-logging',
                    ],
                    [
                        'title' => 'OWASP Application Security Verification Standard: V7 Error Handling and Logging',
                        'link' => 'https://owasp.org/www-project-application-security-verification-standard',
                    ],
                    [
                        'title' => 'OWASP Testing Guide: Testing for Detailed Error Code',
                        'link' => 'https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_for_Error_Code',
                    ],
                    [
                        'title' => 'OWASP Code Review Guide: Reviewing Logging Code',
                        'link' => 'https://owasp.org/www-pdf-archive/OWASP_Code_Review_Guide_v2.pdf',
                    ],
                ]),
                'created_at' => Carbon::now(),
                'updated_at' => Carbon::now(),
            ],
            [
                'code' => 'A10:2021',
                'title' => 'Server-Side Request Forgery (SSRF)',
                'description' => 'SSRF moved up in the Top 10 due to the increased use of cloud services and the continued vulnerability of server-side request forgery. The data shows a relatively low incidence rate with above average testing coverage, along with above-average ratings for Exploit and Impact potential. This category represents the scenario where the security community members are telling us this is important, even though it\'s not illustrated in the data at this time.',
                'cwes' => json_encode([
                    [
                        'code' => 'CWE-918',
                        'name' => 'Server-Side Request Forgery (SSRF)',
                        'link' => 'https://cwe.mitre.org/data/definitions/918.html',
                    ],
                    [
                        'code' => 'CWE-611',
                        'name' => 'Improper Restriction of XML External Entity Reference',
                        'link' => 'https://cwe.mitre.org/data/definitions/611.html',
                    ],
                    [
                        'code' => 'CWE-73',
                        'name' => 'External Control of File Name or Path',
                        'link' => 'https://cwe.mitre.org/data/definitions/73.html',
                    ],
                    [
                        'code' => 'CWE-441',
                        'name' => 'Unintended Proxy or Intermediary',
                        'link' => 'https://cwe.mitre.org/data/definitions/441.html',
                    ],
                ]),
                'references' => json_encode([
                    [
                        'title' => 'OWASP Top 10:2021 - A10 Server-Side Request Forgery (SSRF)',
                        'link' => 'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/',
                    ],
                    [
                        'title' => 'OWASP Cheat Sheet: Server-Side Request Forgery Prevention',
                        'link' => 'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html',
                    ],
                    [
                        'title' => 'OWASP ASVS: Server-Side Request Forgery',
                        'link' => 'https://github.com/OWASP/ASVS/blob/master/4.0/en/0x18-V10-Malicious.md#v101-code-integrity-controls',
                    ],
                    [
                        'title' => 'OWASP Testing Guide: Testing for Server-Side Request Forgery',
                        'link' => 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery',
                    ],
                    [
                        'title' => 'PortSwigger: Server-side request forgery (SSRF)',
                        'link' => 'https://portswigger.net/web-security/ssrf',
                    ],
                    [
                        'title' => 'SSRF Bible',
                        'link' => 'https://cheatsheetseries.owasp.org/assets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet_SSRF_Bible.pdf',
                    ],
                ]),
                'created_at' => Carbon::now(),
                'updated_at' => Carbon::now(),
            ],
        ];

        foreach ($vulnerabilities as $vulnerability) {
            Vulnerability::create($vulnerability);
        }
    }
}
