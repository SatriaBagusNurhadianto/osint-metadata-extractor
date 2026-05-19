import { exiftool } from 'exiftool-vendored';
import sharp from 'sharp';
import { ExifMetadata, MetadataAnomaly, AnomalyType } from '../types/index.js';
import { BaseExtractor } from '../core/BaseExtractor.js';
import Logger from '../utils/Logger.js';

/**
 * Image Metadata Extractor
 * Supports: JPEG, PNG, WEBP, TIFF
 * Extracts: EXIF, GPS, camera info, timestamps, color profiles
 */
export class ImageExtractor extends BaseExtractor {
  async extract(): Promise<ExifMetadata> {
    Logger.info(`Extracting image metadata: ${this.filePath}`);

    try {
      const [exifData, imageInfo, hashes] = await Promise.all([
        this.extractExifData(),
        this.extractImageInfo(),
        this.calculateHashes()
      ]);

      const gps = this.parseGpsData(exifData);
      const anomalies = this.detectAnomalies(exifData, imageInfo);

      const metadata: ExifMetadata = {
        filePath: this.filePath,
        fileName: this.fileName,
        fileSize: this.fileSize,
        mimeType: await this.getMimeType(),
        fileExtension: this.fileName.split('.').pop() || 'unknown',
        fileSignature: this.getFileSignature(),
        createdAt: new Date(exifData.CreateDate || new Date()),
        modifiedAt: new Date(exifData.ModifyDate || new Date()),
        hash: hashes,
        isStripped: this.detectMetadataStripping(exifData),
        anomalies,
        exif: this.sanitizeMetadata(exifData),
        gps,
        imageWidth: imageInfo.width,
        imageHeight: imageInfo.height,
        cameraModel: exifData.Model,
        cameraMake: exifData.Make,
        lensModel: exifData.LensModel,
        iso: exifData.ISO,
        focalLength: exifData.FocalLength,
        aperture: exifData.FNumber,
        exposureTime: exifData.ExposureTime,
        software: exifData.Software,
        dateTimeOriginal: exifData.DateTimeOriginal ? new Date(exifData.DateTimeOriginal) : undefined,
        createDate: exifData.CreateDate ? new Date(exifData.CreateDate) : undefined,
        modifyDate: exifData.ModifyDate ? new Date(exifData.ModifyDate) : undefined,
        userComment: exifData.UserComment,
        artist: exifData.Artist,
        copyright: exifData.Copyright
      };

      Logger.info(`Image extraction successful: ${this.fileName}`, {
        hash: hashes.sha256,
        hasGps: !!gps,
        anomalies: anomalies.length
      });

      Logger.auditExtraction(this.filePath, hashes.sha256, true);
      return metadata;
    } catch (error) {
      Logger.error(`Image extraction failed: ${this.filePath}`, error as Error);
      Logger.auditExtraction(this.filePath, '', false, (error as Error).message);
      throw error;
    }
  }

  /**
   * Extract EXIF data using exiftool-vendored
   */
  private async extractExifData(): Promise<Record<string, any>> {
    try {
      const exifData = await exiftool.read(this.filePath);
      return exifData || {};
    } catch (error) {
      Logger.warn(`Could not extract EXIF from ${this.filePath}`, { error: (error as Error).message });
      return {};
    }
  }

  /**
   * Extract image dimensions and metadata using sharp
   */
  private async extractImageInfo(): Promise<{ width?: number; height?: number }> {
    try {
      const metadata = await sharp(this.filePath).metadata();
      return {
        width: metadata.width,
        height: metadata.height
      };
    } catch (error) {
      Logger.warn(`Could not extract image info: ${this.filePath}`);
      return {};
    }
  }

  /**
   * Parse GPS EXIF data into coordinates
   */
  private parseGpsData(exifData: Record<string, any>) {
    if (!exifData.GPSLatitude || !exifData.GPSLongitude) {
      return undefined;
    }

    return {
      latitude: exifData.GPSLatitude,
      longitude: exifData.GPSLongitude,
      altitude: exifData.GPSAltitude,
      timestamp: exifData.GPSDateStamp,
      formatted: `${exifData.GPSLatitude}° ${exifData.GPSLatitudeRef}, ${exifData.GPSLongitude}° ${exifData.GPSLongitudeRef}`,
      mapUrl: `https://maps.google.com/?q=${exifData.GPSLatitude},${exifData.GPSLongitude}`
    };
  }

  /**
   * Detect image-specific anomalies
   */
  private detectAnomalies(exifData: Record<string, any>, imageInfo: any): MetadataAnomaly[] {
    const anomalies: MetadataAnomaly[] = [];

    // Check for GPS data (hidden location)
    if (exifData.GPSLatitude && exifData.GPSLongitude) {
      anomalies.push({
        type: AnomalyType.HIDDEN_GPS,
        severity: 'high',
        description: 'GPS coordinates detected in image metadata',
        evidence: `${exifData.GPSLatitude}, ${exifData.GPSLongitude}`,
        recommendation: 'Remove GPS data before sharing sensitive photos'
      });
    }

    // Check for metadata stripping
    if (Object.keys(exifData).length < 5) {
      anomalies.push({
        type: AnomalyType.METADATA_STRIPPING,
        severity: 'medium',
        description: 'Minimal EXIF data present - metadata may have been stripped',
        evidence: `Only ${Object.keys(exifData).length} EXIF fields found`
      });
    }

    // Check for suspicious software
    if (exifData.Software && this.isSuspiciousSoftware(exifData.Software)) {
      anomalies.push({
        type: AnomalyType.SUSPICIOUS_SOFTWARE,
        severity: 'low',
        description: 'Unusual software detected in image metadata',
        evidence: exifData.Software
      });
    }

    // Time inconsistency checks
    const timeAnomalies = this.detectTimeInconsistencies(
      exifData.CreateDate ? new Date(exifData.CreateDate) : undefined,
      exifData.ModifyDate ? new Date(exifData.ModifyDate) : undefined,
      exifData.DateTimeOriginal ? new Date(exifData.DateTimeOriginal) : undefined
    );
    anomalies.push(...timeAnomalies);

    return anomalies;
  }

  /**
   * Check for suspicious software names
   */
  private isSuspiciousSoftware(software: string): boolean {
    const suspiciousList = [
      'photoshop',
      'gimp',
      'imagemagick',
      'ffmpeg',
      'fake',
      'spoof',
      'hex'
    ];

    return suspiciousList.some(s => software.toLowerCase().includes(s));
  }

  /**
   * Get MIME type
   */
  private async getMimeType(): Promise<string> {
    const ext = this.fileName.split('.').pop()?.toLowerCase();
    const mimeMap: Record<string, string> = {
      jpg: 'image/jpeg',
      jpeg: 'image/jpeg',
      png: 'image/png',
      webp: 'image/webp',
      tiff: 'image/tiff'
    };
    return mimeMap[ext || ''] || 'image/unknown';
  }

  /**
   * Calculate both hashes
   */
  private async calculateHashes() {
    const [sha256, md5] = await Promise.all([
      this.calculateSHA256(),
      this.calculateMD5()
    ]);
    return { sha256, md5 };
  }
}

export default ImageExtractor;
