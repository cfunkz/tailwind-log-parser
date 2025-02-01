const uploadBtn = document.getElementById("uploadBtn");
const fileInput = document.getElementById("fileInput");
const logContent = document.getElementById("logContent");
const formattedContent = document.getElementById("formattedContent");
const MAX_FILE_SIZE = 25 * 1024 * 1024;

const selectedPatterns = {
    email: true,
    date: true,
    time: true,
    ip: true,
    mac: true,
    ipv6: true,
    hex: true,
    statusCode: true,
    domain: true,
    httpMethods: true,
    netMethods: true,
    logLevel: true,
    filepath: true,
    md5: true,
    sha1: true,
    sha256: true,
    pid: true,
    currency: true,
    coordinates: true,
    ansiEscape: true,
    wallet: true,
    apiKey: false,
    userAgent: true,
    fileExtensions: true,
};

const regexPatterns = {
    email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    date: /\b((Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}|\d{2}\/\d{2}\/\d{4}|\d{2}\.\d{2}\.\d{4})\b/g,
    time: /\b\d{2}:\d{2}:\d{2}\b/g,
    ip: /\b\d{1,3}(\.\d{1,3}){3}\b/g,
    mac: /\b([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b/g,
    ipv6: /\b([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:)\b/g,
    hex: /\b0x[0-9A-Fa-f]+\b/g,
    statusCode: /\b(2\d{2}|3\d{2}|4\d{2}|5\d{2})\b/g,
    domain: /\b(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,6}(?=\s|:|$)/g,
    httpMethods: /\b(?:get|post|put|delete|patch|options|head|trace|connect|port|http|https)\b/gi,
    netMethods: /\b(?:tcp|udp|icmpv6|icmp|ping|pppoe|lan|wan|ttl|hoplimit|syn|ack|data|system|firewall|in|out|hop|proto|protocol)\b/gi,
    logLevel: /\b(?:error|warning|critical|info|debug|notice|success|failure)\b/gi,
    filepath: /(?:\/(?:[\w\s-]+\/)+[\w\s-]+(?:\/|\.[a-zA-Z0-9]+)?)/g,
    md5: /\b[a-f0-9]{32}\b/gi,
    sha1: /\b[a-f0-9]{40}\b/gi,
    sha256: /\b[a-f0-9]{64}\b/gi,
    pid: /\bPID\s\d{1,6}\b/g,
    currency: /(?:£|\$|€|¥|₹|₣|₤|₱|₲|₴|₣|₩|₪)\d+(?:,\d{3})*(?:\.\d{2})?/g,
    coordinates: /\b-?\d{1,3}\.\d{6,},\s?-?\d{1,3}\.\d{6,}\b/g,
    ansiEscape: /\x1B\[[0-9;]*m/g,
    wallet: /\b(?:1|3|bc1)[A-Za-z0-9]{25,34}\b|\b0x[a-fA-F0-9]{40}\b|\b[L|M][A-Za-z0-9]{26,33}\b|\br[a-zA-Z0-9]{25,34}\b|\b[D|9][A-Za-z0-9]{33}\b|\b([A-Za-z0-9]{42})\b/g, // Bitcoin wallet address
    apiKey: /\b[A-Za-z0-9]{32,64}\b/g,
    userAgent: /\b(Mozilla\/[^\s]+|Chrome\/[^\s]+|Safari\/[^\s]+|Edge\/[^\s]+|OPR\/[^\s]+|Firefox\/[^\s]+|MSIE\s[^\s]+|Trident\/[^\s]+)\b/g,
    fileExtensions: /\b(?:[a-zA-Z0-9\s_\\.\-:])+(\.log|\.txt|\.json|\.csv|\.xml|\.html|\.css|\.js|\.lua|\.py|\.sh)\b/g,  // Match file extensions
};

const regexColours = {
    email: 'gray',
    time: 'blue',
    ip: 'purple',
    mac: 'teal',
    ipv6: 'darkviolet',
    hex: 'red',
    statusCode: 'purple',
    filepath: 'orange',
    date: 'blue',
    md5: 'saddlebrown',
    sha1: 'brown',
    sha256: 'darkgoldenrod',
    pid: 'darkgreen',
    currency: 'gold',
    coordinates: 'darkcyan',
    ansiEscape: 'grey',
    httpMethods: {
        get: 'green',
        post: 'blue',
        put: 'darkred',
        delete: 'darkred',
        patch: 'yellow',
        options: 'lightgreen',
        head: 'purple',
        trace: 'magenta',
        connect: 'pink',
        default: 'grey'
    },
    logLevel: {
        error: 'red',
        warning: 'orange',
        critical: 'darkred',
        info: 'grey',
        debug: 'lightgrey',
        notice: 'lightgreen',
        success: 'green',
        failure: 'red'
    },
    netMethods: {
        tcp: 'cyan',
        udp: 'lightblue',
        icmpv6: 'yellowgreen',
        icmp: 'lime',
        ping: 'lightcoral',
        pppoe: 'orangered',
        lan: 'mediumvioletred',
        wan: 'darkorange',
        ttl: 'saddlebrown',
        proto: 'gold',
        hoplimit: 'darkslategray',
        syn: 'tomato',
        ack: 'lightseagreen',
        default: 'grey'
    },
    domain: 'lightblue',
    wallet: 'lightblue',
    apiKey: 'cyan',
    userAgent: 'magenta',
    fileExtensions: 'yellow',
};

function highlightContent(content) {
    Object.keys(selectedPatterns).forEach(pattern => {
        if (selectedPatterns[pattern]) {
            const regex = regexPatterns[pattern];
            const colour = typeof regexColours[pattern] === 'object'
                ? regexColours[pattern]
                : regexColours[pattern];
            content = content.replace(regex, match => {
                let matchColour = colour;
                if (typeof regexColours[pattern] === 'object') {
                    const matchedMethod = match.toLowerCase();
                    matchColour = regexColours[pattern][matchedMethod] || regexColours[pattern].default;
                }
                return `<span class="highlight" style="color: ${matchColour};">${match}</span>`;
            });
        }
    });

    return content;
}

function checkByteContent(content) {
    const textBytes = Array.from(new TextEncoder().encode(content));
    const nonTextCount = textBytes.filter(byte => (byte < 32 || byte > 126) && ![9, 10, 13].includes(byte)).length;
    return (nonTextCount / textBytes.length) < 0.01;
}

function setLogMessage(message, isError = false) {
    logContent.textContent = message;
    if (isError) {
        logContent.classList.remove('text-green-700');
        logContent.classList.add('text-red-700');
    } else {
        logContent.classList.remove('text-red-700');
        logContent.classList.add('text-green-700');
    }
}

function parseLog(content) {
    const rows = content.split('\n');
    return rows;
}

function displayLog(parsedLog) {
    // Clear any existing content
    formattedContent.innerHTML = '';
    parsedLog.forEach(row => {
        const rowDiv = document.createElement('div');
        rowDiv.classList.add('my-2', 'whitespace-pre-wrap');
        // Highlight the content of the row
        const highlightedRow = highlightContent(row);
        rowDiv.innerHTML = `${highlightedRow}<hr class="border-t-2 border-gray-600 mt-2">`;
        // Append the rowDiv to the formattedContent area
        formattedContent.appendChild(rowDiv);
    });
}

function parseCsv(content) {
    const lines = content.split('\n');
    const headers = lines[0].split(',');
    const rows = lines.slice(1).map(line => line.split(','));
    return { headers, rows };
}

function generateTable(headers, rows) {
    let table = '<table class="min-w-full table-auto text-left text-sm">';
    table += '<thead><tr class="bg-gray-700 text-white">';

    headers.forEach(header => {
        table += `<th class="px-4 py-2">${header}</th>`;
    });
    table += '</tr></thead><tbody>';
    rows.forEach(row => {
        table += '<tr class="border-b">';
        row.forEach(cell => {
            const highlightedCell = highlightContent(cell);
            table += `<td class="px-4 py-2">${highlightedCell}</td>`;
        });
        table += '</tr>';
    });
    table += '</tbody></table>';
    return table;
}

function fileUpload() {
    const file = fileInput.files[0];

    if (!file) {
        setLogMessage('Select a log file.', true);
        return;
    }

    if (file.size > MAX_FILE_SIZE) {
        setLogMessage('The selected file exceeds the maximum size limit of 25MB.', true);
        return;
    }

    const fileExtension = file.name.split('.').pop().toLowerCase();
    const reader = new FileReader();

    // Show the loading spinner
    document.getElementById("loadingSpinner").style.display = 'block';
    uploadBtn.disabled = true;  // Disable the upload button

    reader.onload = function(e) {
        const fileContent = e.target.result;

        if (!checkByteContent(fileContent)) {
            setLogMessage('The file contains non-text characters and is not valid.', true);
            // Hide the loading spinner
            document.getElementById("loadingSpinner").style.display = 'none';
            uploadBtn.disabled = false;  // Re-enable the button
            return;
        }

        if (fileExtension === 'csv') {
            const { headers, rows } = parseCsv(fileContent);
            const tableContent = generateTable(headers, rows); // Generate tabble
            formattedContent.innerHTML = tableContent;
            setLogMessage('CSV file uploaded and processed successfully!', false);
        } else {
            const parsedLog = parseLog(fileContent);
            displayLog(parsedLog);
            setLogMessage('File uploaded and processed successfully!', false);
        }

        // Hide the loading spinner after processing
        document.getElementById("loadingSpinner").style.display = 'none';
        uploadBtn.disabled = false;  // Re-enable the button
    };

    reader.onerror = function() {
        setLogMessage('There was an error reading the file.', true);
        document.getElementById("loadingSpinner").style.display = 'none'; // Hide spinner on error
        uploadBtn.disabled = false;  // Re-enable button
    };

    reader.readAsText(file);
}

Object.keys(selectedPatterns).forEach(pattern => {
    const checkbox = document.getElementById(pattern);
    checkbox.addEventListener('change', function() {
        selectedPatterns[pattern] = checkbox.checked;
    });
});

uploadBtn.addEventListener("click", fileUpload);
