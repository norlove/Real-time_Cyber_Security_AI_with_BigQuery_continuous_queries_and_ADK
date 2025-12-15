# Real-time Cyber Security AI with BigQuery continuous queries and Agent Developer Kit (ADK)

This repository contains an end-to-end demonstration of a near real-time cybersecurity threat detection and response system built on Google Cloud using only SQL and agentic prompts. 

This demo leverages a powerful combination of Google Cloud services to create a sophisticated, and yet simple, event-driven architecture. At its core, it uses [BigQuery continuous queries](https://docs.cloud.google.com/bigquery/docs/continuous-queries-introduction) to perform stateful stream processing on high-volume event data, identifying suspicious patterns in near real-time. When a potential threat is detected, it triggers a workflow orchestrated by Google's [Agent Developer Kit (ADK)](https://google.github.io/adk-docs/). This powerful framework allows for the creation of sophisticated AI agents that can perform further investigation, including multi-modal analysis of user screenshots, to determine the true nature of the threat. Confirmed threats are then escalated to a human-operated Security Operations Center (SOC) for final review and action.

**Demo architecture diagram:**

  <img width="1159" height="494" alt="image" src="https://github.com/user-attachments/assets/105144ef-de7f-41c7-8d73-5a1995fbbfa2" />

**Key features:**
- Stateful Stream Processing: Utilizes BigQuery continuous queries to perform windowed aggregations and JOINs on streaming data, enabling complex event correlation and threat detection in near real-time to trigger agentic AI processing.
- Agentic AI: Employs the Agent Developer Kit (ADK) to build and deploy multiple intelligent agents that can autonomously assess and reason about security threats by using tools such as Google Search, BigQuery, visual analysis of screenshots.
- Event-Driven Architecture: Leverages Pub/Sub to create a decoupled, scalable architecture where events from BigQuery trigger actions in ADK.
- Synthetic Data Generation: Uses Google Cloud Colab notebooks to generate realistic, high-volume streams of both benign and malicious network events.
- Multi-Modal Analysis: Demonstrates the use of BigQuery object tables to enable the AI agent to perform visual analysis of user screenshots as part of its investigation.
- Human-in-the-Loop: Includes a simple Security Operations Center (SOC) UI built with Streamlit, allowing human analysts to review and act upon threats escalated by the AI agent.
- Simple agent logging and analytics using [BigQuery Agent Analytics for the Google ADK](https://cloud.google.com/blog/products/data-analytics/introducing-bigquery-agent-analytics).

You can watch a recording of this demo here: **YouTube LINK**

**A few notes**: 
   - BigQuery continuous query stateful data processing (supporting aggregations, windowing, and join operations) are only available via an allowlist only preview. You can register your interest for this preview [HERE](https://forms.gle/PUhnigiWDJDWNbWA9).
   - The steps in this repo are intentionally exhaustive, rather than using a script to auto deploy everything. That's because I find that using auto deploy options substancially reduce learning opportunies. 
   - Some steps require that you provide your own variable names (project IDs, GCS buckets, GCP region, etc), which requires some small code modifications in certain files. Any time you see "# --- UNIQUE PROJECT CONFIGURATION DETAILS BELOW ---" within a file that means you'll have to add your own names here.
   - A special thanks to [Kamal Aboul-Hosn](https://www.linkedin.com/in/kamalaboulhosn/) for providing help with Pub/Sub and [Rachael Deacon-Smith](https://www.linkedin.com/in/rachael-ds/) for providing help with ADK!

Now let's build a cool demo!

----------------------------------------------------------------------------------------------------


**Setting up your project with BigQuery, GCS, and service account resources:**

1. Ensure your project has enabled the [BigQuery Unified API](https://console.cloud.google.com/apis/library/bigqueryunified.googleapis.com), [Vertex AI API](https://console.cloud.google.com/apis/library/aiplatform.googleapis.com), [Pub/Sub API](https://console.cloud.google.com/apis/library/pubsub.googleapis.com), [IAM Service Account Credentials API](https://console.cloud.google.com/marketplace/product/google/iamcredentials.googleapis.com), and [Cloud Resource Manager API](https://console.developers.google.com/apis/api/cloudresourcemanager.googleapis.com)

2. Ensure your user account has the appropriate IAM permissions to administer BigQuery, GCS, Pub/Sub, Vertex AI, and Service Accounts. 

   The required IAM roles are:
   - BigQuery Data Editor (to create BQ resources)
   - BigQuery Connection Admin (to create a remote connection)
   - BigQuery Resource Editor (to create a slot reservation and assignment)
   - BigQuery User (to run the continuous query)
   - Colab Enterprise User (to run the Colab notebooks)
   - Notebook Runtime User (to run the Colab notebooks)
   - Storage Admin (to create GCS buckets and upload files)
   - Service Account Admin (to create a service account)
   - Service Account User (to attach service accounts to services)
   - Project IAM Admin (to assign permissions to the service account)
   - Pub/Sub Editor (to create a Pub/Sub topic and subscription)
   - Vertex AI Administrator (to deploy ADK into Vertex AI Agent Engine)

3. Within the BigQuery editor, create a BigQuery dataset named `Cymbal_Cyber` in your project by running the following SQL query. Note the region used if yours differs:

   ```
   #Creates a dataset named Cymbal_Cyber within your currently selected project
    CREATE SCHEMA IF NOT EXISTS Cymbal_Cyber
    OPTIONS (
      location = "US"
    );
   ```
4. Similarly, create a BigQuery table named `user_access_events` within this dataset for where the raw network access logs will be streamed to.

   ```
   CREATE OR REPLACE TABLE `Cymbal_Cyber.user_access_events`
   (
     event_timestamp TIMESTAMP,
     event_type STRING,
     user_id STRING,
     source_ip STRING,
     assigned_internal_ip STRING,
     device_id STRING,
     device_os STRING,
     user_agent STRING,
     application_name STRING
   )
   PARTITION BY
     DATE(event_timestamp)
   CLUSTER BY
     user_id, assigned_internal_ip, event_type
   OPTIONS(
     description="Logs user login attempts and session creation, linking users to assigned internal IPs."
   );
   ```

5. Create a BigQuery table named `network_events` for where the network connection and firewall access logs will be streamed to.

   ```
   CREATE OR REPLACE TABLE `Cymbal_Cyber.network_events`
   (
     event_timestamp TIMESTAMP,
     event_type STRING,
     user_id STRING,
     source_ip STRING,
     source_port INT64,
     destination_ip STRING,
     destination_port INT64,
     protocol STRING,
     bytes_transferred INT64,
     source_process_name STRING,
     network_domain STRING,
     file_name STRING,
     file_type STRING,
     command_line STRING,
     permission_level_requested STRING,
     file_hash_sha256 STRING
   )
   PARTITION BY
     DATE(event_timestamp)
   CLUSTER BY
     source_ip, user_id, event_type
   OPTIONS(
     description="Logs granular network activity like DNS queries, connections, and file transfers."
   );
   ```

6. Create a BigQuery table named `adk_threat_assessment` for storing the final output and reasoning from the ADK agent workflow for each escalated network threat.

   ```
   CREATE OR REPLACE TABLE `Cymbal_Cyber.adk_threat_assessment` (
     transaction_window_end TIMESTAMP,
     user_id STRING,
     device_id STRING,
     source_ip STRING,
     total_2_min_threat_score INT64,
     agent_decision STRING,
     agent_reason STRING,
     human_decision STRING,
     human_reason STRING,
     alert_payload STRING
   ) OPTIONS (
     description = 'Stores the final output and reasoning from the ADK agent workflow.'
   );
   ```

7. Create a BigQuery remote connection for the object tables named `continuous-query-vertex-ai-connection` in the Cloud Console [using these steps](https://cloud.google.com/bigquery/docs/bigquery-ml-remote-model-tutorial#Create-Connection).

8. After the connection has been created, click "Go to connection", and in the Connection Info pane, copy the service account ID for use in the next step.

   <img width="1622" height="534" alt="image" src="https://github.com/user-attachments/assets/4708d212-db40-46c9-96eb-242711976ac0" />

9. Grant `Vertex AI User` and `Storage Object Viewer` role IAM access to the service account ID you just copied.

10. Create a Service Account named `bq-continuous-query-sa` which will be leveraged to orchestrate the full demo. The service account will be used to run the continuous query, write data to Pub/Sub, perform ADK actions, write to GCS, etc. This service account will require the following permissions:
    - BigQuery Connection User
    - BigQuery Data Editor
    - BigQuery Data Viewer
    - BigQuery User
    - Logs Writer
    - Pub/Sub Publisher
    - Pub/Sub Viewer
    - Service Account Token Creator
    - Service Usage Consumer
    - Storage Object User
    - Vertex AI User (AKA AI Platform User)
    
      <img width="1632" height="720" alt="image" src="https://github.com/user-attachments/assets/78ad1b05-c093-4b37-be59-bd82fc9bd1e2" />

    **NOTE: if you have issues with this demo, it is 9 times out of 10 related to an IAM permissions issue.**
   
11. Within the Cloud Console, create three GCS buckets. 

    **Note: because GCS buckets must be gloably unique, you'll have to choose unique names which will be leveraged later on**
    
     -  cymbal_cyber_adk_staging_bucket_<your_project_id> for staging the Agent Engine files
     -  cymbal-cyber-adk-escalations-bucket_<your_project_id> for the events ADK escalates to the human SOC team
     -  cymbal-cyber-screenshots_<your_project_id> for the screenshot images used in the multi-modal piece of the demo

12. This demo uses ADK to perform a visual analysis of screnshots taken from the user's device at the time these events were generated*. This is done using [BigQuery objects tables](https://docs.cloud.google.com/bigquery/docs/object-table-introduction). We'll first create a BigQuery object table named `screenshots_object_table` by running the following SQL query back in the BigQuery editor:

    ```
    CREATE OR REPLACE EXTERNAL TABLE `Cymbal_Cyber.screenshots_object_table`
    WITH CONNECTION `us.continuous-query-vertex-ai-connection`
    OPTIONS (
      object_metadata = 'SIMPLE',
      # --- UNIQUE PROJECT CONFIGURATION DETAILS BELOW ---
      uris = ['gs://cymbal-cyber-screenshots_<your_project_id>/*'] #Change this to your own GCS bucket name
    );
    ```
    *Note: this demo doesn't actually generate user screenshots. It uses some pre-created ones handled a bit later on in this demo
   
13. Create a BigQuery view on top of the object table named `user_screenshots_view` by running the following SQL query:

    ```
    CREATE VIEW Cymbal_Cyber.user_screenshots_view (user_id, gcs_uri)
    AS (
      SELECT
        -- Extracts 'a.smith' from a URI like 'gs://bucket/a.smith.png'
        REGEXP_EXTRACT(uri, r'([^/]+)\.png$') AS user_id,
        uri AS gcs_uri
      FROM `Cymbal_Cyber.screenshots_object_table`)
    ```

**Streaming user/device network events into BigQuery:**

To demonstrate this environment at scale, we're going to use two Colab Enterprise notebook in BigQuery [ref]. One notebook which continuously runs and generates benign, but realistic events, including occasional firewall violations, failed login attempts, etc. And another malicious users notebook which runs ad-hoc and inserts more malicious networking events.

1. From the BigQuery editor, click the down arrow next to the plus icon and create a new empty notebook. If required click the button to enable the API (there may be other APIs the wizard will have you enable).

   <img width="1542" height="476" alt="image" src="https://github.com/user-attachments/assets/e8d5baf8-a8e5-4910-ab6c-3cf5e2d2794e" />

2. This first notebook will be the benign users notebook. Within the empty notebook code block, paste in the Python code from [HERE](https://github.com/norlove/Real-time_Cyber_Security_AI_with_BigQuery_continuous_queries_and_ADK/blob/main/other_code/benign_users_notebook_code.py). 

   Since this notebook is running within BigQuery, the project details will be captured properly, so there shouldn't be anything you need to change within the code itself. But do review how the code works.

   <img width="1914" height="1302" alt="image" src="https://github.com/user-attachments/assets/e57a7edd-5b1e-4fef-9427-9a91370d31fa" />

3. Create a separate second BigQuery Colab notebook for the malicious events generator. Within the empty notebook code block, paste in the Python code from [HERE](https://github.com/norlove/Real-time_Cyber_Security_AI_with_BigQuery_continuous_queries_and_ADK/blob/main/other_code/malicious_users_notebook_code.py). 

   Similarly, you shouldn't have to modify the code if you are using the natively integrated Colab notebooks within BigQuery.

4. For each notebook, click the Connect button on the right side of the screen to connect the runtime. You may need to select a VPC network to use. Give the connection process a minute to activate, represented by a green check mark.

   <img width="2370" height="316" alt="image" src="https://github.com/user-attachments/assets/82720fd5-06c8-40f2-9ab8-b03fcca0fb87" />

5. Run both notebooks independently. The benign notebook will continue to run in a streaming looped fashion until stopped and the malicious events notebook will only execute once and insert 250 malicious events into the BigQuery tables created previously.

6. Ensure both the `network_events` and `user_access_events` tables in BigQuery are receiving the traffic by running some simple SELECT queries
   First to make sure the benign users notebook is working:
   
   <img width="2162" height="808" alt="image" src="https://github.com/user-attachments/assets/6dbc7e8b-6f0b-466c-9284-a4e2c70d7d71" />

   Then to make sure the malicious users notebook is working:
   
   <img width="2114" height="818" alt="image" src="https://github.com/user-attachments/assets/824a8a8f-37ce-4dae-8034-f02c91e93a11" />

**Setting up Agent Developer Kit (ADK) and the mechanism for triggering ADK:**

Now we'll actually get to the agentic portion of this demo. FYI you'll have to make some code changes in this section. 

Again any code which has "# --- UNIQUE PROJECT CONFIGURATION DETAILS BELOW ---" means you'll have to change something like your project ID, GCS bucket name, etc.

1. Copy all the code within this GitHub repo to your local dev environment. For simplicity, I used Google Cloud Shell within my project.

2. You'll need to install some packages in your local environment. Run the following from the Cloud Shell CLI:
   ```
   pip install "google-adk>=1.15.1" \
   "google-cloud-aiplatform[adk,agent_engines]>=1.119.0" \
   google-cloud-pubsub \
   google-genai \
   google-cloud-logging \
   google-cloud-bigquery \
   google-cloud-storage \
   db-dtypes \
   pandas \
   cloudpickle \
   pydantic \
   python-dotenv 
   ```

3. Copy the 55 screenshots from the [user_screenshots folder of this repo](https://github.com/norlove/Real-time_Cyber_Security_AI_with_BigQuery_continuous_queries_and_ADK/tree/main/user_screenshots) into your GCS bucket `cymbal-cyber-screenshots_<your_project_id>`. 

   Rather than copying/moving the images to your GCS bucket, save some time by running a GCloud command like this:
   ```gcloud storage cp -r user_screenshots/ gs://cymbal-cyber-screenshots_<your_project_id>/```

   You may notice that of the 55 users, 53 users have the same generic screenshot of a BigQuery search console except for the two users g.harris and u.lewis. These two users are our malicious users which will be discussed later on. The other
   screenshots are the same purely for the purposes of avoiding needless busy work.

4. Change to your ADK_code folder and run the command ```python deploy_agent_script.py``` to deploy your ADK agentic framework into the Google Cloud Agent Engine ecosystem
    - You'll see something like this printed if the command runs successfully: `https://us-central1-aiplatform.googleapis.com/v1/projects/271115234308/locations/us-central1/reasoningEngines/7320420874383785984:streamQuery`
    - Copy this text as you'll need it later as your full agent resource ID!
   
      <img width="2252" height="224" alt="image" src="https://github.com/user-attachments/assets/63d714fa-3de8-4df0-b70f-3911d27003ca" />
  
5. Create the Pub/Sub topic named `cymbal_cyber_alerts` to receive the output from your BigQuery continuous query. Don't create any default subscription or anything.

6. Create a Pub/Sub **PUSH** subscription named `adk_agent_trigger` connected to `cymbal_cyber_alerts` to write these events directly to ADK running in Agent Engine.
    - The Endpoint URL will be the full agent resource ID you captured above. Be sure to include everything, including the `:streamQuery` at the end.
    - Check the Enable authentication check box, and provide the service account you created and permissioned before
    - For the Audience (optional) field include the same full agent resource ID you captured above.
    - Check the box "Enable payload unwrapping"
    
      <img width="1022" height="1204" alt="image" src="https://github.com/user-attachments/assets/7516363e-0c2a-4ef9-ae11-89edc44fcc1a" />
   
    - Change the Expiration period to "Never expire"
    - Change the acknowledgement deadline to 600 seconds
    - Click "Add a Transform" and under the "Function Name" box name it "pubsub_to_adk_transform" and copy/paste the contents of the [pubsub_to_adk_transform.js file](https://github.com/norlove/Real-time_Cyber_Security_AI_with_BigQuery_continuous_queries_and_ADK/blob/main/other_code/pubsub_to_adk_transform.js)
    - Click the "Validate" button and ensure the validation passes
    
      <img width="1426" height="1056" alt="image" src="https://github.com/user-attachments/assets/c66dc828-b4df-4e5a-b9e6-572438e3bf17" />

    - Create the Pub/Sub subscription
 
    **NOTE: Anytime you re-deploy your agent in Agent Engine using the ```python deploy_agent_script.py``` script, you'll get a new Agent Engine resource ID. This means you'll have to update BOTH the Endpoint URL and Audience fields within this Pub/Sub subscription in order to ensure the Pub/Sub message is sent to the updated ADK environment.**
   
7. Your agent should now be running and ready to start processing incoming messages. We'll run a few tests to make sure Pub/Sub and ADK are configured correctly shortly.

8. But first, we'll run the Security Operations Center (SOC) UI using Streamlit. So let's install it by running:

   ```pip install streamlit streamlit-autorefresh```


9. Open the Google Cloud Shell and change directories to the other_code folder and start the Streamlit UI app by running:

   ```streamlit run streamlit_app.py --server.enableCORS=false```

   This is one file where you'll have to change some variables.

   <img width="2576" height="610" alt="image" src="https://github.com/user-attachments/assets/02c65172-d190-4d6c-b351-516a8ae6d989" />

10. Click the Local URL link provided with the specific port (`Local URL: http://localhost:8501`). This will open up a new tab where you will see the security alerts as they come in.

    <img width="2282" height="946" alt="image" src="https://github.com/user-attachments/assets/760a173a-7543-45a5-ba33-f8cfb4d26979" />

11. Back within Cloud Shell let Streamlit keep running. Click the plus icon to open another CLI window, change directories to ADK_code, and run the run_local script by running the command:
    ```./run_local.sh``` 
    
    If this is your first run, some packages may need to be installed.

    When prompted, select option 1 to send the malicious event to ADK. You should see a series of messages in your Cloud Shell environment which indicate that the event is being processed by our ADK agent. Once the prompt is "Human handoff request sent. Waiting for a response ..." you'll open your Streamlit tab.

    <img width="2958" height="686" alt="image" src="https://github.com/user-attachments/assets/75622515-4183-495d-bd51-ef0b01a85cf3" />

12. Go back into your Streamlit UI tab where you will see a new alert has been received. If you don't see one, you may have to refresh the window. Click on this alert on the left hand panel and review the details in the right hand panel. Click the "Link to user desktop screenshot" and make sure everything appears correct.

    <img width="2820" height="788" alt="image" src="https://github.com/user-attachments/assets/618a4f64-10ad-41c2-8b10-34e1fa7f8914" />
        -   -   -   -  
    <img width="2526" height="1462" alt="image" src="https://github.com/user-attachments/assets/ec82d2f4-94e6-40cd-b8ee-14a2d34d362d" />

13. Under the Your Response section, check the box for Flase Positive or Genuine Threat and provide a brief comment. Then click the Submit Response button.

    <img width="1822" height="734" alt="image" src="https://github.com/user-attachments/assets/22d8a437-736e-4d5c-8cf8-d3a5718c1f53" />

14. Back in your Cloud Shell tab, you'll see that the human decision was logged successfully and al pending logs should have been sent.

    <img width="1080" height="218" alt="image" src="https://github.com/user-attachments/assets/0b674b8f-2056-4021-b8b2-1824e2b94f33" />

15. You can now query your `adk_threat_assessment` table from BigQuery and confirm that this event and the human decision were successfully logged to BigQuery.

    <img width="2230" height="680" alt="image" src="https://github.com/user-attachments/assets/1f59ec6b-6cbd-4ce1-bc50-cd4b7ce6b950" />

16. You can now be confident that ADK is working properly.

17. You can also query the `agent_events` table to see the logs from your agent

    <img width="2126" height="692" alt="image" src="https://github.com/user-attachments/assets/9b7a067e-ceec-44bb-b87f-bf6bf7c67163" />

18. To test that Pub/Sub is working and triggering ADK properly, use the Cloud Console web UI to navigate to your Pub/Sub topic `cymbal_cyber_alerts`. Within the middle of the page, click the Messages tab and click Publish message

    <img width="1354" height="406" alt="image" src="https://github.com/user-attachments/assets/7e243e91-cef6-4b7c-89e5-0fab8cdd12e8" />

19. Test if your subscription (and therefore ADK) can receive a manually published message by pasting in the below and clicking Publish.
    ```
    {
    "window_end": "2025-12-09T17:42:00Z",
    "user_id": "u.lewis",
    "device_id": "ws-hr-05",
    "source_ip": "175.45.177.32",
    "total_2_min_threat_score": 3000,
    "max_event_score": 205,
    "avg_event_score": 115.38,
    "high_privilege_request_count": 8,
    "suspicious_user_agent_count": 26,
    "risky_file_transfer_count": 4,
    "malicious_command_count": 8,
    "malicious_dns_count": 14
    }
    ```

20. Go back to your Streamlit application tab. It will likely take 1-2 minutes for the event to arrive. Confirm it does.

**Setting up your BigQuery continuous query to tie all this together and trigger ADK in near real-time:**

1. BigQuery continuous queries require a BigQuery Enterprise or Enterprise Plus reservation [[ref](https://cloud.google.com/bigquery/docs/continuous-queries-introduction#reservation_limitations)]. Create one now named "bq-continuous-queries-reservation" in the US multi-region, with a max reservation size of 50 slots, and a slot baseline of 0 slots (to leverage slot autoscaling).
   
   <img width="504" height="536" alt="image" src="https://github.com/user-attachments/assets/9cb9c221-a89c-4a7c-8361-6701b27c367b" />

2. Once the reservation has been created, click on the three dots under Actions, and click "Create assignment". 

   <img width="424" height="402" alt="image" src="https://github.com/user-attachments/assets/7c0fa90c-4e42-4470-b434-4c36c85371b8" />

3. Click Browse and find the project you are using for this demo. Then Select "CONTINUOUS" as the Job Type. Click Create.

   <img width="1046" height="904" alt="image" src="https://github.com/user-attachments/assets/b899e152-1458-4833-8995-52ad4ab35cbd" />

4. You'll now see your assignment created under your reservation:
   
   <img width="2212" height="314" alt="image" src="https://github.com/user-attachments/assets/5c57d83b-4749-4330-b127-814bf4276356" />
      
5. Go back to the BigQuery SQL editor and paste the SQL query found into a new tab [HERE](https://github.com/norlove/Real-time_Cyber_Security_AI_with_BigQuery_continuous_queries_and_ADK/blob/main/other_code/continuous_query.sql)

6.  Before you can run your query, you must enable BigQuery continuous query mode. In the BigQuery editor, click More -> Continuous Query mode

    <img width="1914" height="580" alt="image" src="https://github.com/user-attachments/assets/e3a4b653-13ea-4029-9496-32828922268f" />

7. When the window opens, click the button CONFIRM to enable continuous queries for this BigQuery editor tab.

8. Since we are writing the results of this continuous query to a Pub/Sub topic, you must also run this query using a Service Account [[ref](https://cloud.google.com/bigquery/docs/continuous-queries#choose_an_account_type)]. We'll use the service account we created earlier. Click More -> Query Settings and scroll down to the Continuous query section and select your service account "bq-continuous-query-sa" and click Save.

   <img width="870" height="300" alt="image" src="https://github.com/user-attachments/assets/3c55eeda-4519-4321-9977-1c6b2576116b" />

9. Your continuous query should now be valid.

   <img width="1524" height="716" alt="image" src="https://github.com/user-attachments/assets/8c59b0d6-aa88-400a-ac6d-dd8316fa1b5d" />
    
10. Start up the continuous query (FYI it generally takes 1 - 3 minutes to fully start and begin processing data), start the benign events generator notebook, and when ready initiate the malicious events notebook.

11. Go to Streamlit and confirm you are seeing both benign events, but more importantly the malicious events. Again remember that due to the 2 minute window in the continuous query and ADK processing, it will likely take 3-4 minutes for the events to arrive for the malicious users g.harris and u.lewis.

12. Your demo now works!

13. If you go back into BigQuery and query the `adk_threat_assessment` and `agent_events` tables, there's a variety of interesting insights you can glean. Such as:
    - [How much noise is the Agent filtering out?](https://github.com/norlove/Real-time_Cyber_Security_AI_with_BigQuery_continuous_queries_and_ADK/blob/main/other_code/agent_filtering_noise.sql) This query breaks down the decisions to show what percentage of alerts were auto-closed (False Positives) versus how many required human attention.
    - [Top 5 high-risk devices](https://github.com/norlove/Real-time_Cyber_Security_AI_with_BigQuery_continuous_queries_and_ADK/blob/main/other_code/top_suspicious_devices.sql). This query tells you which devices are most of the escalated threats coming from.
    - [Most used ADK tools with errors](https://github.com/norlove/Real-time_Cyber_Security_AI_with_BigQuery_continuous_queries_and_ADK/blob/main/other_code/tool_usage_and_errors.sql). This query tells you what tool calls your agent made and captures any tool errors.
    - [ADK token cost](https://github.com/norlove/Real-time_Cyber_Security_AI_with_BigQuery_continuous_queries_and_ADK/blob/main/other_code/adk_token_cost.sql). This query determines the number of tokens consumed by each ADK agent, allowing you to estimate costs.
