import { RequestFile, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, failure, safe, violation } from '@tessera/core/static-analysis/shared';

const IMAGE_TYPES = /^image\/(?:png|jpeg|gif|webp|bmp|tiff|avif|heic)$/;
const IMAGE_EXTENSIONS = /\.(?:png|jpe?g|gif|webp|bmp|tiff?|avif|heic)$/i;

export default class ImageDimensions extends Tool<ToolContextType.File> {
    constructor(private readonly config: ToolConfig<'image_dimensions'>) {
        super({
            id: 'image_dimensions',
            displayName: 'Image dimensions',
            category: ToolCategory.Resource,
            contextType: ToolContextType.File,
        });
    }

    override run(context: RequestFile): ToolResult {
        const type = String(context.contentType ?? '').split(';')[0].trim().toLowerCase();
        if (!IMAGE_TYPES.test(type) && !IMAGE_EXTENSIONS.test(String(context.filename ?? ''))) {
            return safe(this.tool);
        }

        const dimensions = ImageDimensions.dimensions(context);
        if (!dimensions) {
            return failure(this.tool, { filename: clip(context.filename), reason: 'missing_dimensions' });
        }

        const { width, height } = dimensions;
        const pixels = width * height;
        const reasons: string[] = [];
        const { maxSide, maxPixels, maxPixelsPerByte } = this.config;
        if (width > maxSide || height > maxSide) reasons.push('side_too_long');
        if (pixels > maxPixels) reasons.push('too_many_pixels');
        // real photos compress far less than maxPixelsPerByte; pixel floods are mostly empty
        if (context.size > 0 && pixels / context.size > maxPixelsPerByte && pixels > 1_000_000) reasons.push('pixel_flood');

        return reasons.length > 0
            ? violation(this.tool, { filename: clip(context.filename), width, height, size: context.size, reasons })
            : safe(this.tool);
    }

    // metadata.width/height when the normalizer decoded the header; otherwise read from the magic bytes,
    // which works for PNG (IHDR), GIF and BMP when enough leading bytes were captured.
    private static dimensions(file: RequestFile): { width: number; height: number } | undefined {
        const metadata = (file.metadata ?? {}) as Record<string, unknown>;
        if (typeof metadata['width'] === 'number' && typeof metadata['height'] === 'number') {
            return { width: metadata['width'], height: metadata['height'] };
        }

        const hex = typeof file.magicBytes === 'string' ? file.magicBytes.replace(/^0x/i, '').replace(/[\s:]/g, '').toLowerCase() : '';
        if (!/^(?:[0-9a-f]{2})+$/.test(hex)) {
            return undefined;
        }
        const bytes = Buffer.from(hex, 'hex');

        if (bytes.length >= 24 && hex.startsWith('89504e47')) {
            return { width: bytes.readUInt32BE(16), height: bytes.readUInt32BE(20) };
        }
        if (bytes.length >= 10 && hex.startsWith('474946')) {
            return { width: bytes.readUInt16LE(6), height: bytes.readUInt16LE(8) };
        }
        if (bytes.length >= 26 && hex.startsWith('424d')) {
            return { width: Math.abs(bytes.readInt32LE(18)), height: Math.abs(bytes.readInt32LE(22)) };
        }
        return undefined;
    }
}
