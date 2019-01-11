import typing

class Link(typing.NamedTuple):
    other_obj: dict
    link_iter: dict
    ltype: str
    def description(self) -> str:
        s = f"[0x{self.other_obj['HashId']:08x}] {self.other_obj['UnitConfigName']} - {self.ltype}"
        params = self.link_iter.get('!Parameters')
        if params:
            s += f" {params}"
        return s

class Map:
    def __init__(self, map_data) -> None:
        self.map_data = map_data
        self.objs: typing.Dict[int, dict] = dict()
        for obj in map_data['Objs']:
            self.objs[obj['HashId']] = obj
            obj['__links'] = []
            obj['__links_to_self'] = []

    def get_obj(self, hashid) -> dict:
        return self.objs[hashid]

    def parse_obj_links(self) -> None:
        for obj in self.map_data['Objs']:
            links = obj.get('LinksToObj', None)
            if not links:
                continue
            for link in links:
                dest_obj = self.objs[link['DestUnitHashId']]
                obj['__links'].append(Link(other_obj=dest_obj, link_iter=link, ltype=link['DefinitionName']))
                dest_obj['__links_to_self'].append(Link(other_obj=obj, link_iter=link, ltype=link['DefinitionName']))

    def build_gen_group(self, obj) -> typing.List[dict]:
        gen_group: typing.Set[int] = set()
        self._do_build_gen_group(obj, gen_group)
        return [self.objs[hashid] for hashid in gen_group]

    def _do_build_gen_group(self, obj, gen_group) -> None:
        hashid = obj['HashId']
        if hashid in gen_group:
            return
        gen_group.add(hashid)
        for link in obj['__links']:
            self._do_build_gen_group(link.other_obj, gen_group)
        for link in obj['__links_to_self']:
            self._do_build_gen_group(link.other_obj, gen_group)
