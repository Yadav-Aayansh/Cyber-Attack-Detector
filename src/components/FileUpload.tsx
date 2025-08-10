import React, { useCallback, useState } from 'react';
import { Upload, File as FileIcon, AlertCircle } from 'lucide-react';
import JSZip from 'jszip';
import pako from 'pako';

interface FileUploadProps {
  onFileSelect: (file: File) => void;
  isLoading?: boolean;
  acceptedTypes?: string[]; // e.g. ['.log', '.txt'] or ['*/*']
  maxSize?: number; // in bytes
}

export function FileUpload({ 
  onFileSelect, 
  isLoading = false, 
  acceptedTypes = ['*/*'],
  maxSize = 100 * 1024 * 1024 // 100MB
}: FileUploadProps) {
  const [dragOver, setDragOver] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const validateFile = (file: File): boolean => {
    if (file.size > maxSize) {
      setError(`File size exceeds ${Math.round(maxSize / (1024 * 1024))}MB limit`);
      return false;
    }

    const allowsAll = acceptedTypes.includes('*/*');

    if (!allowsAll) {
      const extension = '.' + file.name.split('.').pop()?.toLowerCase();
      if (!acceptedTypes.includes(extension) && !file.name.endsWith('.zip') && !file.name.endsWith('.gz')) {
        setError(`File type not supported. Accepted types: ${acceptedTypes.join(', ')}, .zip, .gz`);
        return false;
      }
    }

    setError(null);
    return true;
  };

  const handleFileProcessing = async (file: File) => {
    if (!validateFile(file)) {
      return;
    }

    if (file.name.endsWith('.zip')) {
      try {
        const zip = await JSZip.loadAsync(file);
        const firstFile = Object.keys(zip.files)[0];
        if (firstFile) {
          const decompressedFile = zip.file(firstFile);
          if (decompressedFile) {
            const blob = await decompressedFile.async('blob');
            const newFile = new File([blob], decompressedFile.name);
            onFileSelect(newFile);
          }
        }
      } catch (e) {
        setError('Failed to decompress zip file.');
      }
    } else if (file.name.endsWith('.gz')) {
      try {
        const reader = new FileReader();
        reader.onload = (e) => {
          const compressedData = new Uint8Array(e.target?.result as ArrayBuffer);
          const decompressedData = pako.inflate(compressedData);
          const blob = new Blob([decompressedData]);
          // The original filename is often stored in the gzip header, but pako doesn't expose it easily.
          // We'll create a new filename, removing the .gz extension.
          const newFileName = file.name.replace(/\.gz$/, '');
          const newFile = new File([blob], newFileName);
          onFileSelect(newFile);
        };
        reader.readAsArrayBuffer(file);
      } catch (e) {
        setError('Failed to decompress gzip file.');
      }
    } else {
      onFileSelect(file);
    }
  };

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    
    const files = Array.from(e.dataTransfer.files);
    if (files.length > 0) {
      handleFileProcessing(files[0]);
    }
  }, [onFileSelect, maxSize, acceptedTypes]);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
  }, []);

  const handleInputChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (files && files.length > 0) {
      handleFileProcessing(files[0]);
    }
  }, [onFileSelect, maxSize, acceptedTypes]);

  return (
    <div className="w-full">
      <div
        className={`
          relative border-2 border-dashed rounded-xl p-8 text-center transition-all duration-200
          ${dragOver 
            ? 'border-blue-400 bg-blue-50 dark:bg-blue-900/20' 
            : 'border-gray-300 dark:border-gray-600 hover:border-gray-400 dark:hover:border-gray-500'
          }
          ${isLoading ? 'pointer-events-none opacity-50' : 'cursor-pointer'}
        `}
        onDrop={handleDrop}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
      >
        <input
          type="file"
          className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
          onChange={handleInputChange}
          accept={acceptedTypes.join(',') + ',.zip,.gz'}
          disabled={isLoading}
        />
        
        <div className="flex flex-col items-center space-y-4">
          {isLoading ? (
            <div className="w-12 h-12 border-4 border-blue-500 border-t-transparent rounded-full animate-spin" />
          ) : (
            <Upload className="w-12 h-12 text-gray-400" />
          )}
          
          <div>
            <p className="text-lg font-medium text-gray-900 dark:text-white mb-2">
              {isLoading ? 'Processing...' : 'Upload Log File'}
            </p>
            <p className="text-sm text-gray-500 dark:text-gray-400">
              Drag and drop your log file here, or click to select
            </p>
            <p className="text-xs text-gray-400 dark:text-gray-500 mt-1">
              Supported formats: {acceptedTypes.join(', ')}, .zip, .gz • Max size: {Math.round(maxSize / (1024 * 1024))}MB
            </p>
          </div>
        </div>
      </div>

      {error && (
        <div className="mt-4 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg flex items-start space-x-3">
          <AlertCircle className="w-5 h-5 text-red-500 flex-shrink-0 mt-0.5" />
          <p className="text-sm text-red-700 dark:text-red-300">{error}</p>
        </div>
      )}
    </div>
  );
}