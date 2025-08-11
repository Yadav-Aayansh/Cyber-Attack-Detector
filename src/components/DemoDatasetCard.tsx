import React, { useState } from 'react';
import { Download, Play, Database, ExternalLink, CheckCircle } from 'lucide-react';
import JSZip from 'jszip';
import pako from 'pako';

interface DemoDatasetCardProps {
  onLoadDemo: (file: File) => Promise<void>;
  isLoading: boolean;
}

export function DemoDatasetCard({ onLoadDemo, isLoading }: DemoDatasetCardProps) {
  const [isLoadingDemo, setIsLoadingDemo] = useState(false);

  const handleLoadDemo = async () => {
    setIsLoadingDemo(true);
    try {
      // Fetch the file from the URL
      const response = await fetch(
        'https://raw.githubusercontent.com/Yadav-Aayansh/gramener-datasets/refs/heads/add-server-logs/server_logs.zip',
      );
      
      if (!response.ok) {
        throw new Error(`Failed to fetch demo dataset: ${response.statusText}`);
      }
      
      const blob = await response.blob();
      const file = new File([blob], 'server_logs.zip', { type: 'application/zip' });
      
      // Process the file with decompression logic
      await processAndLoadFile(file);
    } catch (error) {
      console.error('Failed to load demo dataset:', error);
    } finally {
      setIsLoadingDemo(false);
    }
  };

  const processAndLoadFile = async (file: File) => {
    if (file.name.endsWith('.zip')) {
      try {
        const zip = await JSZip.loadAsync(file);
        const firstFile = Object.keys(zip.files)[0];
        if (firstFile) {
          const decompressedFile = zip.file(firstFile);
          if (decompressedFile) {
            const extractedBlob = await decompressedFile.async('blob');
            const extractedFile = new File([extractedBlob], decompressedFile.name, { type: 'text/plain' });
            
            // Call onLoadDemo with the extracted file
            await onLoadDemo(extractedFile);
            return;
          }
        }
      } catch (zipError) {
        console.error('Failed to extract zip file:', zipError);
        throw new Error('Failed to extract demo dataset');
      }
    } else if (file.name.endsWith('.gz')) {
      try {
        const arrayBuffer = await file.arrayBuffer();
        const compressedData = new Uint8Array(arrayBuffer);
        const decompressedData = pako.inflate(compressedData);
        const blob = new Blob([decompressedData]);
        const newFileName = file.name.replace(/\.gz$/, '');
        const newFile = new File([blob], newFileName, { type: 'text/plain' });
        
        await onLoadDemo(newFile);
        return;
      } catch (gzError) {
        console.error('Failed to decompress gzip file:', gzError);
        throw new Error('Failed to decompress demo dataset');
      }
    } else {
      // For non-compressed files, use the original flow
      await onLoadDemo(file);
    }
  };

  return (
    <div className="bg-gradient-to-br from-blue-50 to-indigo-100 dark:from-blue-900/20 dark:to-indigo-900/20 rounded-xl p-6 border-2 border-dashed border-blue-300 dark:border-blue-600 hover:border-blue-400 dark:hover:border-blue-500 transition-all duration-200">
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-blue-500 rounded-lg">
            <Database className="w-6 h-6 text-white" />
          </div>
          <div>
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
              Demo Dataset
            </h3>
            <p className="text-sm text-blue-600 dark:text-blue-400 font-medium">
              Synthetic Apache Server Logs
            </p>
          </div>
        </div>
        <a
          href="https://raw.githubusercontent.com/Yadav-Aayansh/gramener-datasets/add-server-logs/server_logs.zip"
          target="_blank"
          rel="noopener noreferrer"
          className="p-2 text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200 rounded-lg hover:bg-white/50 dark:hover:bg-gray-700/50 transition-colors"
        >
          <ExternalLink className="w-4 h-4" />
        </a>
      </div>

      <p className="text-sm text-gray-600 dark:text-gray-300 mb-4">
        Test the application with pre-generated Apache server logs containing various security threats and attack patterns. 
        Perfect for exploring all detection capabilities without needing your own log files.
      </p>

      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-4 text-xs text-gray-500 dark:text-gray-400">
          <div className="flex items-center space-x-1">
            <Download className="w-3 h-3" />
            <span>ZIP Format</span>
          </div>
          <div className="flex items-center space-x-1">
            <CheckCircle className="w-3 h-3" />
            <span>Ready to Use</span>
          </div>
        </div>

        <button
          onClick={handleLoadDemo}
          disabled={isLoading || isLoadingDemo}
          className="flex items-center space-x-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg font-medium transition-colors"
        >
          {isLoadingDemo ? (
            <>
              <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
              <span>Loading...</span>
            </>
          ) : (
            <>
              <Play className="w-4 h-4" />
              <span>Load Demo</span>
            </>
          )}
        </button>
      </div>

      {isLoadingDemo && (
        <div className="mt-4 p-3 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg">
          <p className="text-sm text-blue-800 dark:text-blue-200">
            Downloading and extracting demo dataset... This may take a moment.
          </p>
        </div>
      )}
    </div>
  );
}