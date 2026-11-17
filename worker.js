{
  "name": "studymind-ai",
  "main": "worker.js",
  "compatibility_date": "2026-06-01",
  "assets": {
    "directory": "./",
    "binding": "ASSETS",
    "run_worker_first": ["/api/*"]
  },
  "ai": { "binding": "AI" },
  "d1_databases": [
    {
      "binding": "DB",
      "database_name": "nbsk-db",
      "database_id": "0ffdaea3-caf7-4a41-a226-c00f1521152d"
    }
  ],
  "observability": { "enabled": true }
}
