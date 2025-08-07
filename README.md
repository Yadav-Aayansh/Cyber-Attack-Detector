# LogGuard Pro - Client-Side Security Log Analysis

A powerful, browser-based security log analysis tool that detects various types of cyber attacks and threats directly in your browser without requiring a backend server.

## Features

- **Client-Side Processing**: All log analysis runs entirely in your browser - no data leaves your machine
- **Multiple Attack Detection**: Detects SQL injection, path traversal, bots, LFI/RFI, WordPress probes, brute force, HTTP errors, and internal IP access
- **Real-Time Analysis**: Instant results with interactive dashboards and visualizations
- **AI-Powered Insights**: Integration with Google Gemini AI for detailed security recommendations
- **Export Capabilities**: Export results to CSV or JSON formats
- **Dark/Light Theme**: Modern, responsive UI with theme switching

## Attack Types Detected

1. **SQL Injection** - Advanced detection of SQL injection attempts including union-based, boolean-based, time-based, and error-based attacks
2. **Path Traversal** - Detection of directory traversal attempts and suspicious path patterns
3. **Bot Detection** - Identification of crawlers, scrapers, and automated tools
4. **LFI/RFI Attacks** - Local and Remote File Inclusion attack detection
5. **WordPress Probes** - WordPress-specific vulnerability scanning attempts
6. **Brute Force** - Password brute force and credential stuffing detection
7. **HTTP Errors** - Analysis of suspicious HTTP error patterns
8. **Internal IP Access** - Detection of internal network access attempts

## Getting Started

### Prerequisites

- Node.js 18+ and npm
- Modern web browser with JavaScript enabled

### Installation

1. Clone the repository:
```bash
git clone https://github.com/Yadav-Aayansh/Cyber-Attack-Detector
cd client
```

2. Install dependencies:
```bash
npm install
```

3. Start the development server:
```bash
npm run dev
```

4. Open your browser and navigate to `http://localhost:5173`

### Usage

1. **Upload Log File**: Click the upload area or drag and drop your log file (supports .log, .txt, and other text formats)

2. **Run Analysis**: Click "Scan" on any attack type card to analyze your logs for that specific threat

3. **View Results**: 
   - Use the Dashboard tab for visual analytics and charts
   - Use the Data Table tab for detailed, filterable results
   - Use the AI Analysis tab for intelligent insights (requires Gemini API key)

4. **Export Data**: Use the CSV or JSON export buttons to save your analysis results

### AI Analysis Setup

To use the AI analysis feature:

1. Get a free Google Gemini API key from [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Enter your API key in the header input field
3. Click "Get AI Analysis" to receive detailed security recommendations

## Log Format Support

The tool supports Apache/Nginx combined log format:
```
IP - - [timestamp] "METHOD /path HTTP/1.1" status bytes "referrer" "user-agent" host server_ip
```

Example:
```
192.168.1.100 - - [01/Jan/2024:12:00:00 +0000] "GET /admin/login.php HTTP/1.1" 200 1234 "-" "Mozilla/5.0..." example.com 10.0.0.1
```

## Architecture

This application runs entirely client-side using:

- **Frontend**: React 18 with TypeScript
- **Styling**: Tailwind CSS with dark/light theme support
- **Charts**: Recharts for data visualization
- **Icons**: Lucide React
- **Build Tool**: Vite
- **Analysis Engine**: Custom JavaScript/TypeScript detection algorithms

### Key Components

- **Log Parser** (`src/utils/logParser.ts`): Parses log files using regex patterns
- **Detectors** (`src/utils/detectors/`): Individual detection algorithms for each attack type
- **Analysis Service** (`src/services/clientSideAnalysis.ts`): Coordinates detection and result processing
- **UI Components**: Modular React components for different views and functionality

## Security & Privacy

- **No Data Transmission**: All log analysis happens locally in your browser
- **No Storage**: Log data is processed in memory and not stored anywhere
- **Privacy First**: Your sensitive log data never leaves your machine

## Development

### Project Structure

```
client/
├── src/
│   ├── components/          # React components
│   ├── hooks/              # Custom React hooks
│   ├── services/           # Analysis and API services
│   ├── utils/              # Utility functions and detectors
│   ├── types/              # TypeScript type definitions
│   └── config/             # Configuration files
├── public/                 # Static assets
└── package.json           # Dependencies and scripts
```

### Building for Production

```bash
npm run build
```

The built files will be in the `dist/` directory, ready for deployment to any static hosting service.

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Built with modern web technologies for maximum performance and security
- Inspired by enterprise security tools but designed for accessibility and ease of use
- Special thanks to the open-source community for the excellent libraries and tools used
