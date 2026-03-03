// 修改前：console.log('Debug:', data)
// 修改后：
import { logger } from '@/core/logger';

logger.debug({ module: 'data-process', data });