import { Module } from '@nestjs/common';
import { CoreLibService } from './core-lib.service';

@Module({
  providers: [CoreLibService],
  exports: [CoreLibService],
})
export class CoreLibModule {}
