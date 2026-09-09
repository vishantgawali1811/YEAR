# Project Documentation: CVE RAG Lookup Tool

## 🎯 Main Motive
The primary motive of this project is to provide a fast, intelligent, and locally-hosted Retrieval-Augmented Generation (RAG) system for querying Common Vulnerabilities and Exposures (CVEs). It streamlines the vulnerability triage process by allowing users to search for specific software products and versions using natural language or direct inputs. The system not only retrieves relevant CVEs from a local dataset but also leverages an AI model (Flan-T5) to classify intent, generate concise summaries, calculate Dynamic Risk Scores (DRS), and provide actionable remediation steps.

## 👥 Target Audience
- **Security Analysts & Researchers:** For quickly triaging vulnerabilities and understanding the risk landscape of specific software stacks.
- **System Administrators & DevOps:** To check if their current infrastructure (specific product versions) is vulnerable and find immediate remediation or patching advice.
- **Developers:** To ensure the dependencies and tools they are using do not have known, critical vulnerabilities.

## 💻 Technologies Used in Detail

### Backend (Python)
- **FastAPI:** A modern, high-performance web framework used to build the RESTful API backend (`app.py`). It handles CORS, routing, and HTTP requests from the frontend.
- **Uvicorn:** An ASGI web server implementation for Python used to run the FastAPI application.
- **Pandas:** A powerful data manipulation library used for loading, filtering, and querying the local vulnerability dataset (typically a CSV file).
- **PyTorch & Hugging Face Transformers:** The core of the AI agent capabilities. Used to load and run local language models (like Flan-T5-Base) for:
  - Parsing natural language queries to extract product and version entities (`parse_query.py`).
  - Classifying user intent (e.g., standard lookup vs. remediation request) (`intent.py`).
  - Generating concise, readable summaries of complex CVE descriptions (`generate.py`).
- **SentencePiece:** A tokenizer dependency required by many Hugging Face models.

### Frontend (JavaScript / React)
- **React 19:** The core UI library used for building the component-based, interactive user interface.
- **Vite:** A blazing fast frontend build tool and development server, replacing Create React App for better performance.
- **React Router DOM:** Used for client-side routing, enabling navigation between the Dashboard, CVE Details, and Analysis pages without reloading the browser.
- **Recharts:** A composable charting library built on React components, used for rendering data visualizations in the Analysis page.
- **Axios:** A promise-based HTTP client used to seamlessly make requests to the FastAPI backend endpoints.
- **Lucide React:** A comprehensive icon library used for consistent, scalable vector icons across the UI.
- **Oxlint:** A fast JavaScript/TypeScript linter used for maintaining code quality.

## 📄 Pages and Their Functions

### 1. Dashboard (`Dashboard.jsx`)
- **Function:** Acts as the primary entry point and main triage matrix.
- **Features:** 
  - Displays high-level KPIs (Total CVEs, Critical, High, Medium, Low counts).
  - Provides a search interface with two modes: **Lookup** and **Remediation**. Users can input a product (e.g., `pan-os`) and version (e.g., `8.1.20`).
  - Renders a data table showing retrieved vulnerabilities, including their CVSS scores, Severities, Attack Vectors, and calculated Dynamic Risk Scores (DRS).
  - Allows users to click on specific CVEs to view deeper details.

### 2. CVE Detail (`CVEDetail.jsx`)
- **Function:** Provides an in-depth view of a single vulnerability.
- **Features:** 
  - Shows comprehensive details retrieved from the dataset for a specific CVE ID.
  - Displays the AI-generated summary of the vulnerability, explaining the impact in plain language.
  - Lists specific remediation steps or mitigation strategies if the user intent or query requested it.

### 3. Analysis (`Analysis.jsx`)
- **Function:** Offers macro-level insights into the vulnerability dataset.
- **Features:** 
  - Utilizes `Recharts` to display graphs and charts.
  - Visualizes trends such as the distribution of severities, most vulnerable products, or historical CVE trends based on the indexed data.

### 4. Terminal (`Terminal.jsx`)
- **Function:** Provides an alternative, power-user interface.
- **Features:** 
  - Mimics a command-line interface directly in the browser.
  - Allows users to type natural language queries (e.g., *"is pan-os 8.1.20 vulnerable?"*) and interact directly with the backend AI agent (`agent.py`) in a chat-like, text-based format.

## ⚙️ Architecture Workflow
1. **User Input:** The user enters a query via the Dashboard or Terminal UI.
2. **API Request:** The frontend sends the query to the FastAPI backend (`/agent-query` or `/lookup`).
3. **Agent Orchestration (`agent.py`):** 
   - Classifies the intent (Lookup vs. Remediation).
   - Parses the query to extract the `Product` and `Version`.
4. **Retrieval (`retrieval.py`):** Uses Pandas to search the loaded dataset for matching vulnerabilities.
5. **Ranking & Generation:** 
   - Calculates Risk Scores (`risk_scoring.py`).
   - Generates summaries or remediation steps using the local AI model (`generate.py`).
6. **Response:** The structured JSON response is sent back to the frontend, which renders the badges, tables, and AI insights.
