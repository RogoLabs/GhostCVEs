# Pipeline Orchestrator

The Pipeline Orchestrator is the master coordinator for the Ghost CVE detection system. It ties together all components of the detection pipeline into a cohesive, automated workflow.

## Overview

The orchestrator coordinates these key stages:

1. **Discovery** - Finding CVE mentions in public sources
2. **Validation** - Checking CVE status against official registries
3. **Storage** - Persisting discoveries and tracking metadata
4. **Resolution Tracking** - Monitoring Ghost CVEs for status changes

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Pipeline Orchestrator                     │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌───────────┐    ┌────────────┐    ┌──────────┐           │
│  │ Discovery │───▶│ Validation │───▶│ Storage  │           │
│  └───────────┘    └────────────┘    └──────────┘           │
│       │                  │                 │                 │
│       │                  │                 │                 │
│  Multiple Sources    CVE Registry     Database              │
│  - GitHub            - Local CVE       - GhostCVE           │
│  - RSS Feeds         - Local NVD       - DiscoverySource    │
│  - ExploitDB         - CVE.org         - HuntRun            │
│  - Vendors                                                   │
│                                                               │
│  ┌──────────────────────────────────────────────────┐       │
│  │           Resolution Tracking                     │       │
│  │  (Monitor RESERVED → PUBLISHED transitions)      │       │
│  └──────────────────────────────────────────────────┘       │
└─────────────────────────────────────────────────────────────┘
```

## Usage

### Basic Usage

```python
from src.pipeline.orchestrator import PipelineOrchestrator
from src.storage.database import DatabaseManager
from src.discovery.github_discovery import GitHubDiscovery
from src.discovery.rss_discovery import RSSFeedDiscovery

# Initialize
db = DatabaseManager("data/ghost_log.db")
orchestrator = PipelineOrchestrator(db)

# Ensure resources are ready
orchestrator.ensure_resources()

# Set up discovery sources
sources = [
    GitHubDiscovery(),
    RSSFeedDiscovery(),
]

# Run the full pipeline
stats = orchestrator.run_full_pipeline(sources)

print(f"Processed {stats.total_discoveries} discoveries")
print(f"Found {stats.ghosts_found} Ghost CVEs")
print(f"Completed in {stats.duration_seconds:.2f}s")
```

### Processing Individual Discoveries

```python
from src.discovery.base import DiscoveryResult
from datetime import datetime

# Create a discovery result
discovery = DiscoveryResult(
    cve_id="CVE-2025-12345",
    source_type="github_commit",
    source_name="owner/repo",
    evidence_url="https://github.com/owner/repo/commit/abc123",
    discovered_at=datetime.utcnow(),
    confidence=0.95,
)

# Process through pipeline
processed = orchestrator.process_discovery(discovery)

if processed and processed.is_ghost:
    print(f"Ghost CVE detected: {processed.cve_id}")
    print(f"Status: {processed.status}")
    print(f"First seen: {processed.first_seen}")
```

### Checking for Resolutions

```python
# Check if any Ghost CVEs have been published
resolved_count = orchestrator.check_for_resolutions()

print(f"{resolved_count} Ghost CVEs were resolved")
```

### Getting Pipeline Statistics

```python
summary = orchestrator.get_pipeline_summary()

print(f"Total CVEs tracked: {summary['total_cves_tracked']}")
print(f"Total Ghost CVEs: {summary['total_ghosts']}")
print(f"Oldest Ghost: {summary['oldest_ghost']}")
print(f"Days in limbo: {summary['oldest_ghost_days']}")
```

## API Reference

### PipelineOrchestrator

Main orchestrator class that coordinates the detection pipeline.

#### Methods

##### `__init__(db_manager: DatabaseManager)`
Initialize the orchestrator with a database manager.

##### `ensure_resources() -> bool`
Ensure all required resources are available (database, registries).

Returns `True` if resources are ready.

##### `process_discovery(discovery: DiscoveryResult) -> Optional[ProcessedCVE]`
Process a single discovery through the pipeline.

**Parameters:**
- `discovery`: DiscoveryResult to process

**Returns:**
- ProcessedCVE if successful, None if error occurred

##### `run_full_pipeline(discovery_sources: List[BaseDiscovery]) -> PipelineStats`
Run the complete pipeline with multiple discovery sources.

**Parameters:**
- `discovery_sources`: List of discovery source instances

**Returns:**
- PipelineStats with execution statistics

##### `check_for_resolutions() -> int`
Check existing Ghost CVEs for resolution (RESERVED → PUBLISHED).

**Returns:**
- Number of Ghost CVEs that were resolved

##### `get_pipeline_summary() -> dict`
Get a summary of the pipeline state.

**Returns:**
- Dictionary with summary information

##### `get_processed_cves() -> List[ProcessedCVE]`
Get list of CVEs processed in the current run.

**Returns:**
- List of ProcessedCVE objects

### ProcessedCVE

Result of processing a CVE through the pipeline.

**Attributes:**
- `cve_id`: str - The CVE identifier
- `is_ghost`: bool - Whether this CVE is a Ghost
- `status`: str - Current registry status
- `first_seen`: datetime - When first discovered
- `sources`: List[str] - Source names that discovered this CVE
- `confidence`: float - Average confidence score
- `description`: Optional[str] - CVE description if available

### PipelineStats

Statistics from a pipeline run.

**Attributes:**
- `total_discoveries`: int - Total CVE discoveries processed
- `unique_cves`: int - Number of unique CVE IDs found
- `ghosts_found`: int - Number of Ghost CVEs identified
- `published_found`: int - Number of published CVEs found
- `sources_used`: List[str] - Discovery source names used
- `errors`: int - Number of errors encountered
- `duration_seconds`: float - Total execution time
- `started_at`: Optional[datetime] - Pipeline start timestamp

## Error Handling

The orchestrator implements robust error handling:

1. **Discovery Errors**: If one source fails, others continue
2. **Validation Errors**: Returns None, logs error, continues
3. **Storage Errors**: Logged and tracked in statistics
4. **Resolution Errors**: Individual CVE errors don't stop batch

All errors are logged with appropriate detail for debugging.

## Performance Considerations

- **Caching**: Validation results are cached for 1 hour
- **Deduplication**: CVEs are deduplicated by ID across sources
- **Batch Processing**: Multiple discoveries processed in sequence
- **Database Sessions**: Properly managed with context managers

## Testing

Comprehensive test coverage (80%+) includes:

- Individual discovery processing
- Full pipeline execution
- Multi-source coordination
- Deduplication
- Error handling
- Resolution detection

Run tests:
```bash
pytest tests/pipeline/test_orchestrator.py -v
```

## Examples

See `examples/pipeline_orchestrator_demo.py` for a complete demonstration.

## Integration

The orchestrator integrates with:

- **Discovery Sources**: All BaseDiscovery implementations
- **Validation**: CVEValidator for registry checks
- **Storage**: DatabaseManager for persistence
- **Registry**: Local CVE repository and NVD data

## Future Enhancements

Potential future additions:

1. Parallel source execution
2. Configurable retry policies
3. Webhook notifications for Ghost detections
4. Real-time streaming mode
5. Machine learning confidence scoring
6. Advanced deduplication strategies

## License

Part of the GhostCVEs project by rogolabs.net
