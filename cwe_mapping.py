# Mapping of vulnerabilities to CWE IDs
# CWE_DATABASE = {
#     'Insecure eval() function': {
#         'description': "Improper Control of Generation of Code ('Code Injection')",
#         'cwe_id': 'CWE-94',
#         'severity': 'High',
#         'remediation': 'Avoid using eval() as it can execute arbitrary code.'
#     },
#     'Hardcoded secret': {
#         'description': 'Use of Hard-coded Credentials',
#         'cwe_id': 'CWE-798',
#         'severity': 'High',
#         'remediation': 'Do not hardcode sensitive information, such as passwords or API keys.'
#     },
#     # Add more vulnerabilities with appropriate CWE mappings here
# }


# //////////////////////////

CWE_DATABASE = {
    'Insecure eval() function': {
        'description': "Improper Control of Generation of Code ('Code Injection')",
        'cwe_id': 'CWE-94',
        'severity': 'High',
        'remediation': 'Avoid using eval() as it can execute arbitrary code.'
    },
    'Hardcoded secret': {
        'description': 'Use of Hard-coded Credentials',
        'cwe_id': 'CWE-798',
        'severity': 'High',
        'remediation': 'Do not hardcode sensitive information, such as passwords or API keys.'
    },
    'SQL Injection': {
        'description': 'Improper Neutralization of Special Elements used in an SQL Command ("SQL Injection")',
        'cwe_id': 'CWE-89',
        'severity': 'Critical',
        'remediation': 'Use prepared statements or parameterized queries to prevent SQL injection.'
    },
    'Cross-Site Scripting (XSS)': {
        'description': 'Improper Neutralization of Input During Web Page Generation ("Cross-site Scripting")',
        'cwe_id': 'CWE-79',
        'severity': 'High',
        'remediation': 'Escape or sanitize user inputs that are rendered on web pages.'
    },
    'Buffer Overflow': {
        'description': 'Buffer Copy without Checking Size of Input ("Buffer Overflow")',
        'cwe_id': 'CWE-120',
        'severity': 'Critical',
        'remediation': 'Always check the size of input before copying to a buffer.'
    },
    'Insecure Direct Object References': {
        'description': 'Missing Authorization for Critical Function ("Insecure Direct Object Reference")',
        'cwe_id': 'CWE-639',
        'severity': 'High',
        'remediation': 'Implement proper access control checks before accessing sensitive resources.'
    },
    'Denial of Service': {
        'description': 'Resource Exhaustion',
        'cwe_id': 'CWE-400',
        'severity': 'High',
        'remediation': 'Implement rate limiting and resource management to prevent denial of service.'
    },
    'Insufficient Logging and Monitoring': {
        'description': 'Insufficient Logging and Monitoring',
        'cwe_id': 'CWE-778',
        'severity': 'Medium',
        'remediation': 'Ensure all security-relevant events are logged and monitored for suspicious activity.'
    },
    'Directory Traversal': {
        'description': 'Path Traversal: A path traversal vulnerability enables an attacker to access files and directories that are stored outside the web root folder.',
        'cwe_id': 'CWE-22',
        'severity': 'High',
        'remediation': 'Validate and sanitize user inputs for file paths.'
    },
    'Path Traversal': {
        'cwe_id': 'CWE-22',
        'description': 'Improperly restricting access to files can allow an attacker to access sensitive files.',
        'severity': 'High',
        'remediation': 'Validate and sanitize user input, and restrict file access appropriately.'
    },
    'Improper Authentication': {
        'description': 'Missing Authentication for Critical Function',
        'cwe_id': 'CWE-306',
        'severity': 'Critical',
        'remediation': 'Implement proper authentication mechanisms for sensitive functions.'
    },
    'Use of Unsafe Reflection': {
        'description': 'Reflection allows an application to inspect and manipulate its own structure and behavior, but it can be exploited.',
        'cwe_id': 'CWE-470',
        'severity': 'Medium',
        'remediation': 'Avoid using reflection to instantiate classes and invoke methods from untrusted sources.'
    },
    'Insecure Cryptographic Storage': {
        'description': 'Insecure Storage of Cryptographic Key',
        'cwe_id': 'CWE-320',
        'severity': 'High',
        'remediation': 'Use strong encryption algorithms and securely manage cryptographic keys.'
    },
    'Race Condition': {
        'description': 'Concurrent Execution using Shared Resource with Improper Synchronization',
        'cwe_id': 'CWE-362',
        'severity': 'High',
        'remediation': 'Implement proper synchronization mechanisms to avoid race conditions.'
    },
    'Missing Input Validation': {
        'description': 'Improper Input Validation',
        'cwe_id': 'CWE-20',
        'severity': 'High',
        'remediation': 'Always validate and sanitize inputs from untrusted sources.'
    },
    'Exposed Sensitive Information': {
        'description': 'Exposure of Sensitive Information to an Unauthorized Actor',
        'cwe_id': 'CWE-200',
        'severity': 'Medium',
        'remediation': 'Limit exposure of sensitive information and implement access controls.'
    },
    'Uncontrolled Resource Consumption': {
        'description': 'Uncontrolled Resource Consumption',
        'cwe_id': 'CWE-400',
        'severity': 'High',
        'remediation': 'Implement limits on resource usage to prevent abuse.'
    },
    'Improper Error Handling': {
        'description': 'Failure to Handle Error Conditions',
        'cwe_id': 'CWE-399',
        'severity': 'Medium',
        'remediation': 'Handle errors gracefully and avoid exposing sensitive information.'
    },
    'Unvalidated Redirects and Forwards': {
        'description': 'Redirection to Untrusted Site',
        'cwe_id': 'CWE-601',
        'severity': 'Medium',
        'remediation': 'Validate and sanitize URLs before redirecting users.'
    },
    'Command Injection': {
        'description': 'Improper Control of Command Execution ("Command Injection")',
        'cwe_id': 'CWE-77',
        'severity': 'Critical',
        'remediation': 'Use secure methods to execute system commands and validate input.'
    },
    'Weak Password Recovery Mechanism': {
        'description': 'Weak Password Recovery Mechanism',
        'cwe_id': 'CWE-640',
        'severity': 'Medium',
        'remediation': 'Implement a strong, multi-factor authentication process for password recovery.'
    },
    'Credential Management Issues': {
        'description': 'Failure to Manage Credentials Properly',
        'cwe_id': 'CWE-256',
        'severity': 'High',
        'remediation': 'Ensure secure storage and transmission of credentials.'
    },
    'Improper Access Control': {
        'description': 'Access Control Mechanism Failure',
        'cwe_id': 'CWE-284',
        'severity': 'Critical',
        'remediation': 'Implement robust access control mechanisms.'
    },
    'Information Leakage': {
        'description': 'Exposure of Information to an Unauthorized Actor',
        'cwe_id': 'CWE-200',
        'severity': 'Medium',
        'remediation': 'Limit information disclosure through proper error handling and response.'
    },
    'HTTP Response Splitting': {
        'description': 'HTTP Response Splitting',
        'cwe_id': 'CWE-113',
        'severity': 'Medium',
        'remediation': 'Sanitize user inputs to prevent manipulation of HTTP responses.'
    },
    'Session Fixation': {
        'description': 'Session Fixation Vulnerability',
        'cwe_id': 'CWE-384',
        'severity': 'High',
        'remediation': 'Regenerate session IDs upon successful authentication.'
    },
    'Use of Deprecated API': {
        'description': 'Use of Deprecated or Unsafe API',
        'cwe_id': 'CWE-676',
        'severity': 'Medium',
        'remediation': 'Avoid using deprecated APIs and replace them with secure alternatives.'
    },
    'Open Redirect': {
        'description': 'Unvalidated Redirects and Forwards',
        'cwe_id': 'CWE-601',
        'severity': 'Medium',
        'remediation': 'Validate all redirect URLs to ensure they lead to trusted locations.'
    },
    'Improperly Controlled Variable': {
        'description': 'Improper Control of a Variable',
        'cwe_id': 'CWE-668',
        'severity': 'High',
        'remediation': 'Ensure variables are controlled properly to prevent unintended consequences.'
    },
    'Insufficient Session Expiration': {
        'description': 'Session Timeout Not Implemented',
        'cwe_id': 'CWE-613',
        'severity': 'Medium',
        'remediation': 'Implement session timeouts and invalidate sessions after a period of inactivity.'
    },
    'Improper Privilege Management': {
        'description': 'Failure to Properly Manage User Privileges',
        'cwe_id': 'CWE-269',
        'severity': 'High',
        'remediation': 'Implement strict role-based access control mechanisms.'
    },
    'Improperly Implemented Authentication': {
        'description': 'Weak Authentication Implementation',
        'cwe_id': 'CWE-287',
        'severity': 'Critical',
        'remediation': 'Use strong authentication mechanisms and enforce password policies.'
    },
    'Race Condition in Security Check': {
        'description': 'Race Condition in Security Check',
        'cwe_id': 'CWE-362',
        'severity': 'High',
        'remediation': 'Use proper locking mechanisms to synchronize critical security checks.'
    },
    'Improper Output Encoding': {
        'description': 'Improper Output Encoding',
        'cwe_id': 'CWE-116',
        'severity': 'High',
        'remediation': 'Ensure all output is properly encoded to prevent injection attacks.'
    },
    'Unrestricted File Upload': {
        'description': 'Unrestricted File Upload',
        'cwe_id': 'CWE-434',
        'severity': 'High',
        'remediation': 'Validate file types and implement restrictions on uploaded files.'
    },
    'Improper Handling of Special Characters': {
        'description': 'Improper Handling of Special Characters in Input',
        'cwe_id': 'CWE-118',
        'severity': 'Medium',
        'remediation': 'Sanitize inputs to handle special characters appropriately.'
    },
    'Ineffective Password Complexity Requirements': {
        'description': 'Weak Password Complexity Requirements',
        'cwe_id': 'CWE-521',
        'severity': 'Medium',
        'remediation': 'Enforce strong password policies and complexity requirements.'
    },
    'Uninitialized Memory Access': {
        'description': 'Accessing Uninitialized Memory',
        'cwe_id': 'CWE-457',
        'severity': 'Medium',
        'remediation': 'Initialize all memory before use.'
    },
    'Insecure Randomness': {
        'description': 'Predictable Random Number Generation',
        'cwe_id': 'CWE-330',
        'severity': 'High',
        'remediation': 'Use a secure random number generator for cryptographic purposes.'
    },
    'Improperly Implemented Access Control': {
        'description': 'Failure to Properly Implement Access Control',
        'cwe_id': 'CWE-284',
        'severity': 'Critical',
        'remediation': 'Enforce proper access control mechanisms for sensitive operations.'
    },
    'Improperly Configured Security Features': {
        'description': 'Improperly Configured Security Features',
        'cwe_id': 'CWE-912',
        'severity': 'High',
        'remediation': 'Regularly review and configure security features appropriately.'
    },
    'Use of Insecure or Weak Cryptographic Algorithms': {
        'description': 'Use of Insecure or Weak Cryptographic Algorithms',
        'cwe_id': 'CWE-327',
        'severity': 'High',
        'remediation': 'Adopt strong cryptographic algorithms and libraries.'
    },
    'Insufficiently Protected Credentials': {
        'description': 'Insufficiently Protected Credentials',
        'cwe_id': 'CWE-312',
        'severity': 'High',
        'remediation': 'Use secure methods to store and transmit credentials.'
    },
    'Incorrect Permission Assignment': {
        'description': 'Incorrect Assignment of Permissions',
        'cwe_id': 'CWE-732',
        'severity': 'High',
        'remediation': 'Ensure proper permission assignments for files and resources.'
    },
    'Improper Error Message Handling': {
        'description': 'Improper Handling of Error Messages',
        'cwe_id': 'CWE-209',
        'severity': 'Medium',
        'remediation': 'Avoid revealing sensitive information in error messages.'
    },
    'Hardcoded Password': {
        'description': 'Hardcoded Password in Source Code',
        'cwe_id': 'CWE-798',
        'severity': 'High',
        'remediation': 'Remove hardcoded passwords and use secure storage mechanisms.'
    },
    'Use of Insecure Protocol': {
        'description': 'Use of Insecure Communication Protocol',
        'cwe_id': 'CWE-284',
        'severity': 'High',
        'remediation': 'Use secure protocols (e.g., HTTPS, SSH) for communication.'
    },
    'Improper Certificate Validation': {
        'description': 'Failure to Properly Validate SSL/TLS Certificates',
        'cwe_id': 'CWE-295',
        'severity': 'High',
        'remediation': 'Ensure proper validation of SSL/TLS certificates in all connections.'
    },
    'Reliance on Security through Obscurity': {
        'description': 'Security through Obscurity is Not Sufficient',
        'cwe_id': 'CWE-55',
        'severity': 'Medium',
        'remediation': 'Implement robust security measures rather than relying solely on obscurity.'
    },
    'Improperly Handled Exception': {
        'description': 'Improper Handling of Exception Conditions',
        'cwe_id': 'CWE-253',
        'severity': 'Medium',
        'remediation': 'Ensure exceptions are handled appropriately and do not disclose sensitive information.'
    },
    'Use of Insecure Functions': {
        'description': 'Use of Unsafe Functions',
        'cwe_id': 'CWE-676',
        'severity': 'High',
        'remediation': 'Avoid using functions known to be insecure and replace them with safer alternatives.'
    },
    'Lack of Account Lockout Mechanism': {
        'description': 'Failure to Implement Account Lockout Mechanism',
        'cwe_id': 'CWE-307',
        'severity': 'Medium',
        'remediation': 'Implement account lockout mechanisms to mitigate brute-force attacks.'
    },
    'Insufficient Protection Against CSRF': {
        'description': 'Cross-Site Request Forgery (CSRF)',
        'cwe_id': 'CWE-352',
        'severity': 'High',
        'remediation': 'Use anti-CSRF tokens to protect against cross-site request forgery attacks.'
    },
    'Exposure of Session IDs in URL': {
        'description': 'Session ID Exposure through URL',
        'cwe_id': 'CWE-942',
        'severity': 'Medium',
        'remediation': 'Avoid exposing session IDs in URLs and use secure cookies instead.'
    },
    'Misconfigured Cross-Origin Resource Sharing (CORS)': {
        'description': 'CORS Misconfiguration',
        'cwe_id': 'CWE-345',
        'severity': 'Medium',
        'remediation': 'Configure CORS policies correctly to prevent unauthorized access.'
    },
    'Hardcoded API Key': {
        'description': 'Hardcoded API Key in Source Code',
        'cwe_id': 'CWE-798',
        'severity': 'High',
        'remediation': 'Do not hardcode API keys; use environment variables or secure vaults.'
    },
    'Race Condition in Access Control': {
        'description': 'Race Condition in Access Control Check',
        'cwe_id': 'CWE-362',
        'severity': 'High',
        'remediation': 'Ensure access control checks are atomic and properly synchronized.'
    },
    'Improper Session Management': {
        'description': 'Weak Session Management',
        'cwe_id': 'CWE-613',
        'severity': 'High',
        'remediation': 'Implement secure session management practices.'
    },
    'Insecure Direct Object Reference (IDOR)': {
        'description': 'Insecure Direct Object Reference',
        'cwe_id': 'CWE-639',
        'severity': 'High',
        'remediation': 'Validate user access before allowing access to resources.'
    },
    'Improper URL Validation': {
        'description': 'Improper URL Validation',
        'cwe_id': 'CWE-601',
        'severity': 'Medium',
        'remediation': 'Validate URLs to prevent unwanted redirection.'
    },
    'Insecure API Exposure': {
        'description': 'Insecure Exposure of APIs',
        'cwe_id': 'CWE-118',
        'severity': 'High',
        'remediation': 'Secure APIs and limit access to authorized users only.'
    },
    'Improper Handling of Sensitive Information': {
        'description': 'Improper Handling of Sensitive Data',
        'cwe_id': 'CWE-307',
        'severity': 'High',
        'remediation': 'Ensure sensitive information is encrypted and handled properly.'
    },
    'Exposure of Sensitive Information in Comments': {
        'description': 'Sensitive Information Exposure in Code Comments',
        'cwe_id': 'CWE-209',
        'severity': 'Medium',
        'remediation': 'Avoid including sensitive information in code comments.'
    },
    'Failure to Restrict URL Access': {
        'description': 'Failure to Restrict Access to URLs',
        'cwe_id': 'CWE-285',
        'severity': 'High',
        'remediation': 'Implement proper access controls for URL resources.'
    },
    'Lack of Encryption for Sensitive Data': {
        'description': 'Failure to Encrypt Sensitive Data',
        'cwe_id': 'CWE-311',
        'severity': 'High',
        'remediation': 'Encrypt sensitive data both at rest and in transit.'
    },
    'Hardcoded Credentials in Configuration Files': {
        'description': 'Hardcoded Credentials in Configuration',
        'cwe_id': 'CWE-798',
        'severity': 'High',
        'remediation': 'Remove hardcoded credentials and utilize secure configuration management.'
    },
    'Improper Handling of Redirects': {
        'description': 'Improper Handling of URL Redirects',
        'cwe_id': 'CWE-601',
        'severity': 'Medium',
        'remediation': 'Validate all redirects to ensure they lead to trusted sites.'
    },
    'Insecure Access to Temporary Files': {
        'description': 'Insecure Access to Temporary Files',
        'cwe_id': 'CWE-22',
        'severity': 'Medium',
        'remediation': 'Secure access to temporary files and restrict permissions.'
    },
    'Improperly Managed Session Timeouts': {
        'description': 'Failure to Implement Session Timeouts',
        'cwe_id': 'CWE-613',
        'severity': 'Medium',
        'remediation': 'Set reasonable session timeout periods.'
    },
    'Insufficient Randomness in Session Tokens': {
        'description': 'Insufficient Randomness in Generated Session Tokens',
        'cwe_id': 'CWE-330',
        'severity': 'High',
        'remediation': 'Use secure random generation for session tokens.'
    },
    'Improper Error Message Logging': {
        'description': 'Sensitive Information in Error Logs',
        'cwe_id': 'CWE-209',
        'severity': 'Medium',
        'remediation': 'Ensure error messages do not contain sensitive information.'
    },
    'Uncontrolled Access to Critical Resources': {
        'description': 'Uncontrolled Access to Sensitive Resources',
        'cwe_id': 'CWE-284',
        'severity': 'Critical',
        'remediation': 'Implement strict access controls for critical resources.'
    },
    'Failure to Use Strong Encryption': {
        'description': 'Failure to Use Strong Encryption Algorithms',
        'cwe_id': 'CWE-327',
        'severity': 'High',
        'remediation': 'Adopt strong encryption standards for data protection.'
    },
    'Insecure HTTP Headers': {
        'description': 'Insecure HTTP Headers Configuration',
        'cwe_id': 'CWE-16',
        'severity': 'Medium',
        'remediation': 'Implement security headers to protect against common attacks.'
    },
    'Insecure Defaults': {
        'description': 'Insecure Default Settings',
        'cwe_id': 'CWE-664',
        'severity': 'Medium',
        'remediation': 'Review and secure default settings in applications.'
    },
    'Improper Initialization of Variables': {
        'description': 'Improper Initialization of Variables',
        'cwe_id': 'CWE-457',
        'severity': 'Medium',
        'remediation': 'Ensure all variables are properly initialized before use.'
    },
    'Missing Anti-CSRF Tokens': {
        'description': 'Missing Anti-CSRF Tokens in Forms',
        'cwe_id': 'CWE-352',
        'severity': 'High',
        'remediation': 'Include anti-CSRF tokens in all state-changing requests.'
    },
    'Insecure Configuration Management': {
        'description': 'Insecure Configuration Management Practices',
        'cwe_id': 'CWE-120',
        'severity': 'High',
        'remediation': 'Regularly review and securely manage application configurations.'
    },
    'Improper Certificate Validation': {
        'description': 'Improper Validation of SSL/TLS Certificates',
        'cwe_id': 'CWE-295',
        'severity': 'High',
        'remediation': 'Ensure proper validation of SSL/TLS certificates.'
    },
    'Hardcoded Encryption Keys': {
        'description': 'Hardcoded Encryption Keys in Source Code',
        'cwe_id': 'CWE-798',
        'severity': 'High',
        'remediation': 'Remove hardcoded encryption keys and use secure key management practices.'
    },
    'Insufficient Server-Side Validation': {
        'description': 'Insufficient Validation on Server Side',
        'cwe_id': 'CWE-20',
        'severity': 'High',
        'remediation': 'Ensure robust validation of all incoming data on the server side.'
    },
    'Improper Use of JavaScript': {
        'description': 'Improper Use of JavaScript Libraries',
        'cwe_id': 'CWE-111',
        'severity': 'Medium',
        'remediation': 'Regularly review and update JavaScript libraries for security.'
    },
    'Misconfigured Security Features': {
        'description': 'Misconfigured Security Settings',
        'cwe_id': 'CWE-912',
        'severity': 'High',
        'remediation': 'Regularly audit security configurations and enforce best practices.'
    },
    'Use of Non-Secure Protocols': {
        'description': 'Using Non-Secure Communication Protocols',
        'cwe_id': 'CWE-319',
        'severity': 'High',
        'remediation': 'Use secure protocols (e.g., HTTPS) to transmit sensitive data.'
    },
    'Failure to Restrict Access to Administrative Interfaces': {
        'description': 'Failure to Restrict Access to Admin Interfaces',
        'cwe_id': 'CWE-285',
        'severity': 'Critical',
        'remediation': 'Implement strict access controls for administrative interfaces.'
    },
    'Misconfigured Default Credentials': {
        'description': 'Default Credentials Not Changed',
        'cwe_id': 'CWE-288',
        'severity': 'High',
        'remediation': 'Change default credentials and enforce strong passwords.'
    },
    'Improperly Managed API Keys': {
        'description': 'Improper Management of API Keys',
        'cwe_id': 'CWE-798',
        'severity': 'High',
        'remediation': 'Securely manage API keys and avoid hardcoding them in source code.'
    },
    'Use of Deprecated Libraries': {
        'description': 'Use of Deprecated Libraries',
        'cwe_id': 'CWE-676',
        'severity': 'Medium',
        'remediation': 'Replace deprecated libraries with supported alternatives.'
    },
    'Excessive Data Exposure': {
        'description': 'Excessive Exposure of Data',
        'cwe_id': 'CWE-200',
        'severity': 'Medium',
        'remediation': 'Limit the amount of data exposed in responses to authorized users.'
    },
    'Poorly Designed Authentication Mechanism': {
        'description': 'Poorly Designed Authentication Mechanism',
        'cwe_id': 'CWE-287',
        'severity': 'Critical',
        'remediation': 'Implement strong, secure authentication practices.'
    },
    'Failure to Sanitize Inputs': {
        'description': 'Failure to Sanitize User Inputs',
        'cwe_id': 'CWE-20',
        'severity': 'High',
        'remediation': 'Always sanitize and validate inputs from untrusted sources.'
    },
    'Improper Handling of File Uploads': {
        'description': 'Improper Handling of Uploaded Files',
        'cwe_id': 'CWE-434',
        'severity': 'High',
        'remediation': 'Validate and restrict file types during uploads.'
    },
    'Insufficient Protection of Application Data': {
        'description': 'Insufficient Protection of Application Data',
        'cwe_id': 'CWE-311',
        'severity': 'High',
        'remediation': 'Implement encryption for sensitive application data.'
    },
    'Improper URL Redirection': {
        'description': 'Improper Redirection of URLs',
        'cwe_id': 'CWE-601',
        'severity': 'Medium',
        'remediation': 'Validate all redirects to trusted locations only.'
    },
    'Use of Predictable Tokens': {
        'description': 'Use of Predictable Security Tokens',
        'cwe_id': 'CWE-330',
        'severity': 'High',
        'remediation': 'Generate unpredictable and strong security tokens.'
    },
    'Failure to Implement Strong Security Controls': {
        'description': 'Failure to Implement Adequate Security Controls',
        'cwe_id': 'CWE-664',
        'severity': 'High',
        'remediation': 'Implement a comprehensive security framework.'
    },
    


        'Use of Hardcoded Credentials': {
        'description': 'Use of Hard-coded Credentials',
        'cwe_id': 'CWE-798',
        'severity': 'High',
        'remediation': 'Do not hardcode sensitive information, such as passwords or API keys.'
    },
    'Server Information Exposure': {
        'description': 'Exposure of Information to an Unauthorized Actor',
        'cwe_id': 'CWE-200',
        'severity': 'Medium',
        'remediation': 'Limit the information revealed by server responses and error messages.'
    },
    'Debug Mode Enabled': {
        'description': 'Debugging Features Enabled in Production',
        'cwe_id': 'CWE-330',
        'severity': 'High',
        'remediation': 'Disable debugging features and detailed error messages in production environments.'
    },
    'Input Validation Issues': {
        'description': 'Improper Input Validation',
        'cwe_id': 'CWE-20',
        'severity': 'High',
        'remediation': 'Always validate and sanitize inputs from untrusted sources.'
    },
    'Authentication and Authorization Flaws': {
        'description': 'Improper Authentication or Authorization',
        'cwe_id': 'CWE-306',
        'severity': 'Critical',
        'remediation': 'Implement strong authentication and authorization mechanisms.'
    },
    'Data Encryption and Secure Communication': {
        'description': 'Failure to Encrypt Sensitive Data',
        'cwe_id': 'CWE-311',
        'severity': 'High',
        'remediation': 'Encrypt sensitive data both at rest and in transit using strong protocols.'
    },
    'Exception Handling and Logging': {
        'description': 'Insufficient Logging and Monitoring',
        'cwe_id': 'CWE-778',
        'severity': 'Medium',
        'remediation': 'Log security-relevant events and handle exceptions without revealing sensitive information.'
    },
    'Dependency Management': {
        'description': 'Use of Vulnerable Dependencies',
        'cwe_id': 'CWE-937',
        'severity': 'High',
        'remediation': 'Regularly update and manage dependencies to mitigate known vulnerabilities.'
    },
    'Proper Use of API and Integration Points': {
        'description': 'Improper Use of APIs and Integration Points',
        'cwe_id': 'CWE-295',
        'severity': 'High',
        'remediation': 'Use secure methods to access APIs and validate input/output appropriately.'
    },
    'Cross-Site Request Forgery (CSRF) Protections': {
        'description': 'Cross-Site Request Forgery (CSRF)',
        'cwe_id': 'CWE-352',
        'severity': 'High',
        'remediation': 'Use anti-CSRF tokens in all state-changing requests.'
    },
    'Server-Side Code Execution Validation': {
        'description': 'Improper Control of Generation of Code',
        'cwe_id': 'CWE-94',
        'severity': 'Critical',
        'remediation': 'Validate inputs and avoid executing untrusted code on the server.'
    },
    'Business Logic Errors': {
        'description': 'Business Logic Flaws',
        'cwe_id': 'CWE-840',
        'severity': 'High',
        'remediation': 'Review business logic thoroughly to ensure proper validation and controls.'
    },
    'Code Quality and Best Practices': {
        'description': 'Lack of Code Quality Practices',
        'cwe_id': 'CWE-690',
        'severity': 'Medium',
        'remediation': 'Implement code reviews and follow coding standards to improve code quality.'
    },
    'Insecure Use of Cryptography': {
        'description': 'Use of Weak Cryptographic Algorithms',
        'cwe_id': 'CWE-327',
        'severity': 'High',
        'remediation': 'Use strong cryptographic algorithms and properly manage keys.'
    },
}

# Function to retrieve CWE details based on the vulnerability name
def get_cwe_details(vulnerability_name):
    return CWE_DATABASE.get(vulnerability_name, {
        'description': 'No description available',
        'cwe_id': 'N/A',
        'severity': 'N/A',
        'remediation': 'No remediation available'
    })

