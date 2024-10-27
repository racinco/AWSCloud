![AWS Lambda](https://github.com/user-attachments/assets/853b6a54-890f-4ef5-a4db-b4473da5e2ba)

# SIMPLE AWS LAMBDA CODE
Hello guys! This is your friendly newbie here with a simple idea for beginners that wishes to learn API calls, AWS API Gateway, Lambda and S3. The concept is easy and simple, I just want to somehow create a Lambda function that can search details for CVE and write them in a text file and save that text file in S3 so that I can retrieve them later.

How this works is quite simple:

The idea here is simple:

1.  The API gateway will server as the trigger point for the AWS lambda to execute the provided source code.
2.  The source code will initiate an API call to NIST CVE endpoint and will fetch data based on your provided parameters. Once the NIST CVE endpoint returns the parameters requested the code will also process the information and save the data in a file.
3.  The code will call the S3 Bucket endpoint for data to be saved into that file.
4.  Then the user may be able to download that text file for more information.

# API GATEWAY
![image](https://github.com/user-attachments/assets/7b5e492e-9ca4-40ae-aec3-5a249be8eddf)

1. Create your own API Gateway through ( API Gatweway > APIs > Create API)
2. Select REST API
3. By creating a REST API, you can send parameters to the API Gateway and then the Lambda Function Attached will be able to retrieve these parameters

# LAMBDA FUNCTION
![image](https://github.com/user-attachments/assets/85455afe-1ecb-479d-b756-becbc1473e71)

1. Create a Lambda Function.
2. In my Case I used python for my Lambda Function

# S3 BUCKET 
![image](https://github.com/user-attachments/assets/ff4913ac-f347-4bf6-b641-208993f847b0)

1. Create an S3 bucket through (Amazon S3 > Buckets > Create Bucket)
