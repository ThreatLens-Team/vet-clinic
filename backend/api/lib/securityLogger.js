import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

/*
    Get the current directory because this project uses ES modules
    and does not have __dirname available automatically.
*/
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/*
    Store IAM security logs in a dedicated logs directory
    inside the backend/api folder.
*/
const logDirectory = path.join(__dirname, "..", "logs");
const logFile = path.join(logDirectory, "iam-security.log");

/*
    Create the logs directory if it does not already exist.
*/
if (!fs.existsSync(logDirectory)) {
    fs.mkdirSync(logDirectory, { recursive: true });
}

/*
    Write one structured IAM security event to the log file.
*/
export function logSecurityEvent(event) {
    try {
        const securityEvent = {
            timestamp: new Date().toISOString(),
            ...event,
        };

        /*
            Convert the event to JSON and place each event
            on its own line for easier Splunk ingestion.
        */
        const logLine = JSON.stringify(securityEvent) + "\n";

        fs.appendFileSync(logFile, logLine, "utf8");
    } catch (err) {
        /*
            A logging failure should not crash the Vet Clinic application.
        */
        console.error("Security logging error:", err);
    }
}
