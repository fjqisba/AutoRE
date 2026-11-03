"""从 Il2CppDumper 的 script.json 提取有界候选，保留重载和共享地址。"""
import argparse
import json
from pathlib import Path


def integer(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('script_json', type=Path)
    filters = parser.add_mutually_exclusive_group(required=True)
    filters.add_argument('--contains', help='名称包含的文本，不区分大小写')
    filters.add_argument('--exact', help='精确方法名，保留所有同名条目')
    parser.add_argument('--limit', type=int, default=30, help='0 表示导出全部匹配')
    parser.add_argument('--pe-image-base', type=integer, help='已确认 PE 的 IDA 基址；Address 按 RVA 解释')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.limit < 0:
        parser.error('--limit 不能为负数')
    if args.pe_image_base is not None and args.pe_image_base < 0:
        parser.error('--pe-image-base 不能为负数')
    data = json.loads(args.script_json.read_text(encoding='utf-8-sig'))
    methods = data['ScriptMethod']
    if not isinstance(methods, list):
        raise ValueError('ScriptMethod 应为数组')
    selected = [m for m in methods if
                (m.get('Name') == args.exact if args.exact is not None else
                 args.contains.casefold() in m.get('Name', '').casefold())]
    rows = []
    for method in (selected[:args.limit] if args.limit else selected):
        address = integer(method['Address'])
        row = dict(method)
        row['address_hex'] = hex(address)
        if args.pe_image_base is not None:
            # 原值为 0 常表示没有可用地址，不能映射成模块基址处的函数。
            row['pe_va'] = hex(args.pe_image_base + address) if address else None
        rows.append(row)
    report = {'matched_total': len(selected), 'returned': len(rows),
              'truncated': len(rows) < len(selected),
              'address_semantics': 'PE RVA' if args.pe_image_base is not None else 'raw; verify module format',
              'methods': rows}
    output = json.dumps(report, ensure_ascii=False, indent=2)
    if args.output:
        if args.output.resolve() == args.script_json.resolve():
            parser.error('输出不能覆盖输入 script.json')
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output + '\n', encoding='utf-8')
        print(json.dumps({k: v for k, v in report.items() if k != 'methods'}, ensure_ascii=False))
    else:
        print(output)


if __name__ == '__main__':
    main()
