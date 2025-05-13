# Project Files Structure
* `webapp`: it's a *react* and *flask* project that utilizes the CVE graph database (inside they're both defined the *front* and *back* end);
* `retrieve_data.py`: script used to retrieve all sort of info related to vulnetabilities (CNA, CVE, CWE, CAPEC);
* `create_graph.py`: script that uses the files retrieved by the `retrieve_data.py` and creates a *Neo4j* graph database;

# Prerequisite
* Have installed locally *Neo4j Desktop* with *APOC* libraries;
* *Node* and *npm* (by installing node you'll also get npm);
* *Yarn* (after you've installed node, run `npm install --global yarn`)
* *Python* then run `pip install -r requirements.txt` to install required libraries

# How to Run This Code
* `retrieve_data.py`/ `create_graph.py`: 
   * Create a `.env` file in the root folder containing all the credantials, like:
     ```
     NEO4J_URI=...
     NEO4J_USERNAME=...
     NEO4J_PASSWORD=...
     NIST_API_KEY=...
     VIRUSTOTAL_API_KEY=...
     SHODAN_API_KEY=...
     ABUSEIPDB_API_KEY=...
     SECTRAILS_API_KEY=...
     ```
     Where `NIST_API_KEY` refers to the key provided by the *NIST* and used to call their API, meanwhile `NEO4J_[...]` are all the parameters for connecting to a graph database in the *Neo4j Desktop* application
     `VIRUSTOTAL_API_KEY`, `SHODAN_API_KEY` , `ABUSEIPDB_API_KEY` , `SECTRAILS_API_KEY` are all the API keys of the respective services, you can get them by creating an account on their websites 
   * Then, simply run these script using *Python3* (i.e. `python3 [script]`). If you encounter some errors make sure to have locally insalled all the dependencies
* `webapp`: 
   *  Inside the `client` and `server_cve` folder run `yarn install`
   *  Create a `.env` file in the `server_cve` and `server_ioc` folder containing all the credentials necessary to connect to a local Neo4j graph database (*see previous points*) and the API keys for the various IoC services
   *  Run `index.py` inside the `server_ioc` folder
   *  Then run in 2 separate terminals `yarn start`, one being inside the `client` folder and the other one being inside the `server_cve` one