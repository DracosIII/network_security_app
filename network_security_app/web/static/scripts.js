async function fetchData() {
    const response = await fetch('/data');
    const data = await response.json();
    const tableBody = document.querySelector('#data-table tbody');
    tableBody.innerHTML = '';

    if (data.error) {
        tableBody.innerHTML = `<tr><td colspan="5">${data.error}</td></tr>`;
        return;
    }

    for (const [device, details] of Object.entries(data)) {
        const row = `
            <tr>
                <td>${device}</td>
                <td>${details.ip_address}</td>
                <td>${details.open_ports.join(', ')}</td>
                <td>${details.vulnerabilities ? 'Oui' : 'Non'}</td>
                <td>${details.recommendations}</td>
            </tr>
        `;
        tableBody.innerHTML += row;
    }
}

async function fetchActions() {
    const response = await fetch('/actions');
    const actions = await response.json();
    const tableBody = document.querySelector('#actions-table tbody');
    tableBody.innerHTML = '';

    if (actions.error) {
        tableBody.innerHTML = `<tr><td colspan="3">${actions.error}</td></tr>`;
        return;
    }

    for (const action of actions) {
        const row = `
            <tr>
                <td>${action.type}</td>
                <td>${action.details}</td>
                <td>${action.date}</td>
            </tr>
        `;
        tableBody.innerHTML += row;
    }
}

fetchData();
fetchActions();

// Gestion de l'affichage en temps réel des logs
const logsContainer = document.getElementById('logs-container');
socket.on("log_update", (data) => {
    const msg = data.message;
    const p = document.createElement("p");
    p.textContent = msg;
    logsContainer.appendChild(p);
    // Défilement automatique vers le bas
    logsContainer.scrollTop = logsContainer.scrollHeight;
});

async function fetchDevices() {
  try {
    const response = await fetch('/data');
    const data = await response.json();
    console.log("Données récupérées :", data); // Vérifier le JSON reçu
    const tbody = document.getElementById('devices-tbody');
    if (!tbody) {
      console.error("Élément 'devices-tbody' non trouvé !");
      return;
    }
    tbody.innerHTML = ""; // Vider les anciennes données

    // Vérifier que data est un objet non vide
    if (!data || Object.keys(data).length === 0) {
      tbody.innerHTML = "<tr><td colspan='4'>Aucun appareil détecté</td></tr>";
      return;
    }

    Object.entries(data).forEach(([deviceName, info]) => {
      const row = document.createElement("tr");

      const cellName = document.createElement("td");
      cellName.textContent = deviceName;
      row.appendChild(cellName);

      const cellIp = document.createElement("td");
      cellIp.textContent = info.ip_address || "";
      row.appendChild(cellIp);

      const cellMac = document.createElement("td");
      cellMac.textContent = info.mac_address ? info.mac_address : "Non défini";
      row.appendChild(cellMac);

      const cellPorts = document.createElement("td");
      if (info.open_ports && info.open_ports.length > 0) {
        cellPorts.textContent = info.open_ports.join(", ");
      } else {
        cellPorts.textContent = "Aucun port ouvert";
      }
      row.appendChild(cellPorts);

      tbody.appendChild(row);
    });
  } catch (error) {
    console.error("Erreur lors de la récupération des appareils:", error);
  }
}

// Actualiser les périphériques toutes les 5 secondes
setInterval(fetchDevices, 5000);
fetchDevices();

// Gestion de l'affichage des logs via SocketIO
// const logsContainer = document.getElementById('logs-container');
socket.on("log_update", (data) => {
  const p = document.createElement("p");
  p.textContent = data.message;
  logsContainer.appendChild(p);
  // Faire défiler vers le bas
  logsContainer.scrollTop = logsContainer.scrollHeight;
});
