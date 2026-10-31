"""Manual registry-metadata monitoring; no target execution or duplicate alerts."""
import hashlib
import json
import re
from packaging.version import Version
from .inputs import InputError
from .network import Fetcher
from .pypi import package_name, release_metadata, version_name, scan_pypi


def snapshot(data):
    version=version_name(data['info'].get('version'))
    Version(version)
    items=data.get('urls')
    if not isinstance(items,list) or len(items)>1000:
        raise InputError('Unsupported watch artifact metadata')
    files=[]
    for item in items:
        if not isinstance(item,dict) or not isinstance(item.get('digests'),dict):
            raise InputError('Malformed watch artifact identity')
        name,digest=item.get('filename'),item['digests'].get('sha256')
        if not isinstance(name,str) or len(name)>256 or not isinstance(digest,str) or not re.fullmatch('[a-f0-9]{64}',digest):
            raise InputError('Watch metadata lacks a valid artifact identity')
        files.append({'filename':name,'sha256':digest,'yanked':bool(item.get('yanked'))})
    return {'version':version,'artifacts':sorted(files,key=lambda f:f['filename']),
            'coverage':'Latest-release registry declarations only; artifact bytes are not downloaded by the metadata check.'}


def watch_once(store, *, fetcher=None, scan_new=False):
    own=fetcher is None
    fetcher=fetcher or Fetcher()
    results=[]
    try:
        for watched in store.watchlist():
            name=watched['name']
            try:
                current=snapshot(release_metadata(fetcher,name))
                event=store.observe(name,current)
                item={'name':name,**event}
                if scan_new and event['status']!='UNCHANGED':
                    try:
                        report=scan_pypi(name,current['version'],fetcher=fetcher)
                        from .policy import apply_policy
                        report=apply_policy(report,store.get_policy())
                        store.save(report)
                        item['scan_id']=report.scan_id
                    except (InputError,OSError,ValueError) as exc:
                        item['scan_error']=str(exc)[:300]
                results.append(item)
            except (InputError,OSError,ValueError) as exc:
                store.watch_error(name, exc)
                results.append({'name':name,'status':'ERROR','error':str(exc)[:300]})
    finally:
        if own: fetcher.close()
    return results
