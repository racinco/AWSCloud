import json
import requests
import boto3
from datetime import datetime

# Initialize the S3 client
s3 = boto3.client('s3')

# Set constants
BUCKET_NAME = 'lambdas3save'  # Using the constant directly
FILE_EXTENSION = "my_file.txt"

 
# CVE NISTS
API_ENDPOINT = "https://services.nvd.nist.gov/rest/json/"

CVE_HISTORY = API_ENDPOINT + "cvehistory/2.0"
CVE_DETAILS = API_ENDPOINT + "cves/2.0"


"""

@parameters
    cpeName
    cveId = provide CVE ID of a vulnerability 
    cveTag 
    cvssV2Metrics 
    cvssV2Severity 
    cvssV4Metrics 
    cvssV4Severity 
    cweId 
    hasCertAlerts
    keywordSearch
    lastModStartDate & lastModEndDate 

"""  

def search_cve(keywordSearch, startDate, endDate):
    url = CVE_DETAILS
    params = {
        'keywordSearch' : keywordSearch,
        'pubStartDate' : f"{startDate}T00:00:00.000",
        'pubEndDate' : f"{endDate}T00:00:00.000"
    }
    
    try:
        response = requests.get(url, params=params, timeout=20)
        # response = requests.get(url, params=params)
        response.raise_for_status()  # Raise an error for bad responses
        
        cve_data = response.json()
        
        return cve_data

    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return "error"
    
def format_cve(cve_results):

    vulnerabilities_list = cve_results['vulnerabilities']

    # List of keys you want to keep in each 'cve' dictionary
    keys_to_keep = ["id", "vulnStatus" , "descriptions", "metrics"]

    # Iterate over the list of dictionaries
    for vuln in vulnerabilities_list:
        # Get the cve dictionary from each element
        cve_dict = vuln.get('cve', {})
        
        # Find keys to remove in the cve dictionary
        keys_to_remove = [key for key in cve_dict if key not in keys_to_keep]
        
        # Remove the unwanted keys
        for key in keys_to_remove:
            del cve_dict[key]

    sorted_vulnerabilities = []

    for vuln in vulnerabilities_list:
        cve_details = vuln['cve']
        # Get the first description
        description_value = cve_details['descriptions'][0].get('value', 'No description available')
        
        # Get the impact score
        impact_score = cve_details['metrics']['cvssMetricV31'][0].get('impactScore', 0)
        
        # Append the CVE ID, status, description, and impact score to a new list
        sorted_vulnerabilities.append({
            "id": cve_details.get('id'),
            "vulnStatus": cve_details.get('vulnStatus'),
            "description": description_value,
            "impactScore": impact_score
        })

    # Sort by impact score descending
    sorted_vulnerabilities.sort(key=lambda x: x['impactScore'], reverse=True)

    results_string = ""
    for vuln in sorted_vulnerabilities:
        results_string += f"CVE ID: {vuln['id']}\n"
        results_string += f"Vuln Status: {vuln['vulnStatus']}\n"
        results_string += f"Description: {vuln['description']}\n"
        results_string += f"Impact Score: {vuln['impactScore']}\n"
        results_string += "-" * 40 + "\n"
    return results_string

def s3_bucket(file_content):
    # Get the current date and time, format it to avoid issues with special characters
    current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    
    # Use the constant directly instead of fetching from environment
    bucket_name = BUCKET_NAME  # Or, use os.environ['BUCKET_NAME'] if it's an environment variable
    file_name = f"{current_time}_{FILE_EXTENSION}"  # Generate the file name

    try:
        # Upload the content to the specified S3 bucket
        file_content_bytes = file_content.encode('utf-8')
        s3.put_object(Bucket=bucket_name, Key=file_name, Body=file_content_bytes, ContentType='text/plain')
        # s3.put_object(Bucket=BUCKET_NAME, Key=file_name, Body=file_content_bytes.encode('utf-8'), ContentType='text/plain')
        return {
            'statusCode': 200,
            'body': json.dumps(f'Successfully uploaded {file_name} to {bucket_name}')
        }
    
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps(f'Error: {str(e)}')
        }

def main(event):
     # Call the search_cve function and store the results
    params = event.get('queryStringParameters', {})
    
    keywordSearch = params.get('keywordSearch', 'Microsoft')
    startDate = params.get('startDate', '2021-08-30')
    endDate = params.get('endDate', '2021-09-30')
    
    cve_results = search_cve(keywordSearch,startDate,endDate)
    results = format_cve(cve_results)
    return s3_bucket(results)
    
def lambda_handler(event, context):
    value = main(event)
    return value   

