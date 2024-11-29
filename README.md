To address the two issues you've mentioned, we need to modify the `generate_sbom` function in the script. Here are the changes required:

1. For the version in `bom-ref`, we need to preserve the comma instead of replacing it with a dot.
2. The `bom-ref` format should only replace the first '/' after 'pkg:' with a '-', and keep subsequent '/' characters.

Here's how we can update the relevant part of the `generate_sbom` function:

```python
if purl:
    name = package.get('name')
    version = clean_version(package.get('versionInfo'))
    
    # Construct bom-ref and purl with version
    pkg_parts = purl.split('/', 2)
    if len(pkg_parts) == 3:
        bom_ref = f"{pkg_parts[0]}-{pkg_parts[1]}/{pkg_parts[2]}-{version}"
    else:
        bom_ref = f"{purl}-{version}"
    bom_ref = bom_ref.replace('@', '-')
    purl_with_version = f"{purl}@{version}"
    
    components.append({
        "bom-ref": bom_ref,
        "type": "library",
        "name": name,
        "version": version,
        "purl": purl_with_version
    })
```

This modification will:

1. Keep the comma in the version for both `bom-ref` and `purl`.
2. Format the `bom-ref` as requested, only replacing the first '/' after 'pkg:' with a '-'.

For example, with these changes:
- A version like "9,<10" will be preserved in both `bom-ref` and `purl`.
- The `bom-ref` will look like "pkg:composer-laravel/lumen-framework-5.2.0" instead of "pkg:composer-laravel-lumen-framework-5.2.0".

These adjustments should resolve the issues you've identified with the SBOM generation.

Citations:
[1] https://stackoverflow.com/questions/5202648/adding-bom-unicode-signature-while-saving-file-in-python
[2] https://cyclonedx.org/docs/1.6/json/
[3] https://cyclonedx.org/docs/1.5/json/
[4] https://forum.kicad.info/t/kibom-python-bom-generation-tool/3038
[5] https://docs.python.org/3/howto/unicode.html
[6] https://www.youtube.com/watch?v=IyOhu_zwrMo
[7] https://github.com/hwstar/BOMtools
[8] https://github.com/CycloneDX/cyclonedx-python/issues/391
