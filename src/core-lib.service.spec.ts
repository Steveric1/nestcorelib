import { Test, TestingModule } from '@nestjs/testing';
import { CoreLibService } from './core-lib.service';

describe('CoreLibService', () => {
  let service: CoreLibService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [CoreLibService],
    }).compile();

    service = module.get<CoreLibService>(CoreLibService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
