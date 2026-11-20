import argparse,tempfile
from pathlib import Path
from .ingest import initialize,load
from .rules import evaluate, action
from .report import export,verify
def main():
    p=argparse.ArgumentParser(description='离线证据判定工具');sub=p.add_subparsers(dest='command',required=True)
    d=sub.add_parser('demo');d.add_argument('--workdir')
    i=sub.add_parser('init');i.add_argument('--db',required=True);i.add_argument('--config',required=True)
    l=sub.add_parser('load');l.add_argument('--db',required=True);l.add_argument('path')
    e=sub.add_parser('evaluate');e.add_argument('--db',required=True)
    r=sub.add_parser('report');r.add_argument('--db',required=True);r.add_argument('--out',required=True)
    v=sub.add_parser('verify');v.add_argument('--db',required=True);v.add_argument('--sandbox');v.add_argument('--out')
    for name in ('plan','execute','recheck'):
        x=sub.add_parser(name);x.add_argument('--db',required=True);x.add_argument('--sandbox');x.add_argument('--out')
    rq=sub.add_parser('request-triage');rq.add_argument('--db',required=True);rq.add_argument('--id',required=True);rq.add_argument('--subjects',required=True);rq.add_argument('--due',required=True)
    rf=sub.add_parser('request-fulfill');rf.add_argument('--db',required=True);rf.add_argument('--id',required=True)
    hp=sub.add_parser('handoff-prepare');hp.add_argument('--db',required=True);hp.add_argument('--id',required=True);hp.add_argument('--recipient',required=True);hp.add_argument('--subjects',required=True);hp.add_argument('--expires',required=True)
    ha=sub.add_parser('handoff-ack');ha.add_argument('--db',required=True);ha.add_argument('--id',required=True);ha.add_argument('--recipient',required=True);ha.add_argument('--hashes',required=True);ha.add_argument('--at',required=True)
    ro=sub.add_parser('recall-open');ro.add_argument('--db',required=True);ro.add_argument('--id',required=True);ro.add_argument('--request',required=True);ro.add_argument('--transfer',required=True)
    rs=sub.add_parser('recall-submit');rs.add_argument('--db',required=True);rs.add_argument('--id',required=True);rs.add_argument('--recipient',required=True);rs.add_argument('--receipts',required=True)
    mi=sub.add_parser('inventory-register');mi.add_argument('--db',required=True);mi.add_argument('--id',required=True);mi.add_argument('source')
    ms=sub.add_parser('inventory-inspect');ms.add_argument('--db',required=True);ms.add_argument('--id',required=True)
    df=sub.add_parser('delivery-freeze');df.add_argument('--db',required=True);df.add_argument('--id',required=True)
    df.add_argument('--inventory',required=True);df.add_argument('--recipient',required=True)
    df.add_argument('--purpose',required=True);df.add_argument('--route',required=True,choices=('hold_new','coarsen_new'))
    df.add_argument('--spec',required=True);df.add_argument('--package-dir',required=True)
    dr=sub.add_parser('delivery-resume');dr.add_argument('--db',required=True);dr.add_argument('--id',required=True);dr.add_argument('--package-dir',required=True)
    dv=sub.add_parser('delivery-verify');dv.add_argument('--db',required=True);dv.add_argument('--id',required=True);dv.add_argument('--package-dir',required=True)
    dp=sub.add_parser('delivery-report');dp.add_argument('--db',required=True);dp.add_argument('--id',required=True)
    di=sub.add_parser('delivery-inspect');di.add_argument('--db',required=True);di.add_argument('--id',required=True)
    a=p.parse_args()
    if a.command=='demo':
        work=Path(a.workdir or tempfile.mkdtemp(prefix='evidence-'));work.mkdir(parents=True,exist_ok=True);db=work/'ledger.db';fixture=Path(__file__).resolve().parent.parent/'fixtures'
        initialize(db,fixture/'config.json');load(db,fixture/'events.jsonl');print(evaluate(db));print(export(db,work/'report.json'))
    elif a.command=='init':print(initialize(a.db,a.config))
    elif a.command=='load':print(load(a.db,a.path))
    elif a.command=='evaluate':print(evaluate(a.db))
    elif a.command=='report':print(export(a.db,a.out))
    elif a.command=='verify':
        from . import rules
        checks=verify(a.db)
        if hasattr(rules,'verify_decisions'):checks+=rules.verify_decisions(a.db)
        target=rules.verify_target(a.db,a.sandbox) if a.sandbox and hasattr(rules,'verify_target') else []
        if a.out:
            import json
            out=Path(a.out);out.parent.mkdir(parents=True,exist_ok=True)
            out.write_text(json.dumps({'integrity_problems':checks,'target':target},ensure_ascii=False,indent=2),encoding='utf-8')
            out.with_suffix('.md').write_text('# 独立对账\n\n'+'\n'.join(f'- {x}' for x in target),encoding='utf-8')
        print({'integrity_problems':checks,'target':target})
    elif a.command=='request-triage':
        from .requests import triage
        print(triage(a.db,a.id,a.subjects.split(','),a.due))
    elif a.command=='request-fulfill':
        from .requests import fulfill
        print(fulfill(a.db,a.id))
    elif a.command=='handoff-prepare':
        from .handoff import prepare
        print(prepare(a.db,a.id,a.recipient,a.subjects.split(','),a.expires))
    elif a.command=='handoff-ack':
        import json
        from .handoff import acknowledge
        print(acknowledge(a.db,a.id,a.recipient,json.loads(Path(a.hashes).read_text(encoding='utf-8')),a.at))
    elif a.command=='recall-open':
        from .recall import open_case
        print(open_case(a.db,a.id,a.request,a.transfer))
    elif a.command=='recall-submit':
        import json
        from .recall import submit
        print(submit(a.db,a.id,a.recipient,json.loads(Path(a.receipts).read_text(encoding='utf-8'))))
    elif a.command=='inventory-register':
        from .minimization import register
        print(register(a.db,a.id,a.source))
    elif a.command=='inventory-inspect':
        from .minimization import inspect
        print(inspect(a.db,a.id))
    elif a.command=='delivery-freeze':
        import json
        from .requests import freeze_delivery
        spec=json.loads(Path(a.spec).read_text(encoding='utf-8'))
        print(freeze_delivery(a.db,a.id,a.inventory,a.recipient,a.purpose,a.route,spec,a.package_dir))
    elif a.command=='delivery-resume':
        from .requests import resume_delivery
        print(resume_delivery(a.db,a.id,a.package_dir))
    elif a.command=='delivery-verify':
        from .requests import verify_delivery
        print(verify_delivery(a.db,a.id,a.package_dir))
    elif a.command=='delivery-report':
        from .requests import delivery_report
        print(delivery_report(a.db,a.id))
    elif a.command=='delivery-inspect':
        from .delivery import inspect as delivery_inspect
        print(delivery_inspect(a.db,a.id))
    else:print(action(a.command,a.db,sandbox=getattr(a,'sandbox',None),out=getattr(a,'out',None)))
if __name__=='__main__':main()
