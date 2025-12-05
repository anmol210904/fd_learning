import requests
import json
from datetime import datetime
import time

# --- Configuration ---
# URL to fetch pending tasks
FETCH_URL = "https://api.upskillmafia.com/lms/assignment/mentor/fetch-tasks"
# URL to submit feedback
FEEDBACK_URL = "https://api.upskillmafia.com/lms/assignment/mentor/provide-feedback"

# Base parameters for the fetch request. The 'page' will be updated in a loop.
fetch_params = {
    "courseId": "680c86ea364f718dc17b69b1",
    "page": 1,
    "pageSize": 20,
    "status": "pending",
    "sortBy": "submittedOn",
    "sortOrder": "latest"
}

# Common headers for both requests
# 🔒 IMPORTANT: If this API requires a login, you MUST uncomment the
# Authorization line and add your Bearer Token.
headers = {
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "keep-alive",
    "Origin": "https://chat.tutedude.com",
    "Referer": "https://chat.tutedude.com/",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0",
    # "Authorization": "Bearer YOUR_TOKEN_HERE",  # <--- ADD YOUR TOKEN HERE IF NEEDED
}

# Create a separate header config for the feedback POST request, adding Content-Type
feedback_headers = headers.copy()
feedback_headers["Content-Type"] = "application/json"


# --- Logging Setup ---
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
log_file = f"api_log_{timestamp}.txt"

def log_message(message):
    """Appends a message to the log file and prints it to the console."""
    print(message)
    with open(log_file, "a", encoding="utf-8") as log:
        log.write(message + "\n")

# --- Main Script ---
log_message(f"Script started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
log_message("--- Phase 1: Fetching All Pending Assignments from Pages 1 to 5 ---")

all_assignments = []
try:
    # Loop through pages 1 to 5 to collect all assignments first
    for page_number in range(1, 6):
        fetch_params["page"] = page_number
        log_message(f"\nFetching assignments from page {page_number}...")
        
        response = requests.get(FETCH_URL, headers=headers, params=fetch_params)
        log_message(f"Requesting URL: {response.url}")
        log_message(f"Fetch Status Code: {response.status_code}")

        if response.status_code == 200:
            data = response.json()
            assignments_on_page = data.get("tasks", [])
            if assignments_on_page:
                log_message(f"Found {len(assignments_on_page)} assignments on page {page_number}.")
                all_assignments.extend(assignments_on_page)
            else:
                log_message(f"No more assignments found on page {page_number}. Stopping fetch.")
                break # Exit the loop if a page has no assignments
        else:
            log_message(f"[ERROR] Failed to fetch page {page_number}. Status: {response.status_code}. Aborting fetch.")
            break
        
        # Brief pause between requests
        time.sleep(0.5)

    log_message(f"\n--- Fetch Complete: Collected a total of {len(all_assignments)} assignments. ---")

    if not all_assignments:
        log_message("No pending assignments found to process. Exiting.")
    else:
        log_message("\n--- Phase 2: Processing and Approving Each Assignment ---")
        
        approved_count = 0
        for i, assignment in enumerate(all_assignments, 1):
            try:
                # Extract all the necessary information from the assignment object
                email = assignment.get("email")
                course_id = assignment.get("courseId")
                task_info = assignment.get("task", {})
                assignment_id = task_info.get("assignmentId")
                task_name = task_info.get("taskName")
                
                course_name = "ethicalhacking"

                if not all([email, course_id, assignment_id, task_name]):
                    log_message(f"[WARNING] Skipping assignment due to missing data: {assignment}")
                    continue

                # Construct the JSON payload for the feedback request
                feedback_payload = {
                    "status": "approved",
                    "email": email,
                    "mentorEmail": "",
                    "courseId": course_id,
                    "assignmentId": assignment_id,
                    "courseName": course_name,
                    "taskName": task_name,
                    "feedback": "Fine."
                }
                
                log_message(f"\n({i}/{len(all_assignments)}) Submitting approval for {email} | Task: {task_name}")
                log_message(f"  -> Payload: {json.dumps(feedback_payload)}")

                # Make the POST request to provide feedback
                feedback_response = requests.post(
                    FEEDBACK_URL, 
                    headers=feedback_headers, 
                    data=json.dumps(feedback_payload)
                )

                log_message(f"  -> Feedback API Response Status: {feedback_response.status_code}")
                
                if feedback_response.status_code in [200, 201]:
                     log_message("  -> SUCCESS: Assignment approved.")
                     approved_count += 1
                else:
                     log_message(f"  -> FAILED: Server responded with: {feedback_response.text}")
                
                time.sleep(1) 

            except Exception as e:
                log_message(f"[ERROR] Failed to process an assignment: {assignment}. Error: {e}")
        
        log_message("\n--- Summary ---")
        log_message(f"Total assignments processed: {len(all_assignments)}")
        log_message(f"Successfully approved: {approved_count}")

except requests.exceptions.RequestException as e:
    log_message(f"[CRITICAL ERROR] A network error occurred: {e}")
except json.JSONDecodeError:
    log_message(f"[CRITICAL ERROR] Could not parse JSON from response. Body was: {response.text}")

log_message(f"\nScript finished. All logs are saved to: {log_file}")

