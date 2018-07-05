#!/usr/bin/env python3
import argparse
import collections
import csv
import itertools
import json
import re
import os
import sys

import byml
from texttable import Texttable

object_names = json.load(open(os.path.dirname(os.path.realpath(__file__)) + "/botw_names.json"))

parser = argparse.ArgumentParser(description='Parses and prints information about scaling config.')
parser.add_argument('byml', type=argparse.FileType('rb'), help='Path to LevelSensor.byml')
parser.add_argument('--kill_table_csv', type=argparse.FileType('w'), nargs='?',
                    help='Path to output CSV for kill table information')
parser.add_argument('--enemy_scaling_csv', type=argparse.FileType('w'), nargs='?',
                    help='Path to output CSV for enemy scaling information')
parser.add_argument('--weapon_scaling_csv', type=argparse.FileType('w'), nargs='?',
                    help='Path to output CSV for weapon scaling information')
args = parser.parse_args()

config = byml.Byml(args.byml.read()).parse()

def pairwise(iterable):
    a, b = itertools.tee(iterable)
    next(b, None)
    return zip(a, b)

def get_table_printer() -> Texttable:
    t = Texttable(max_width=130)
    t.set_deco(Texttable.BORDER | Texttable.HEADER | Texttable.VLINES)
    t.set_precision(2)
    return t

def write_csv(file, header, rows) -> None:
    if not file:
        return
    writer = csv.writer(file)
    writer.writerow(header)
    writer.writerows(rows)

def print_kill_table() -> None:
    print("Points per enemy kill")
    header = ["Enemy", "Pts per kill"]
    rows: list = []

    t = get_table_printer()
    t.header(header)
    t.set_cols_align(["l", "r"])
    for flag in config["flag"]:
        object_name = re.fullmatch("Defeated_(\w+)_Num", flag["name"])
        if object_name:
            rows.append([object_names[object_name.group(1)], flag["point"]])
    t.add_rows(rows, header=False)
    print(t.draw())

    write_csv(args.kill_table_csv, header, rows)

def print_enemy_scaling_list() -> None:
    print("\nEnemy scaling list")
    multiplier = config["setting"]["Level2EnemyPower"]
    print("Note: 1 point = %.3f enemy points" % multiplier)

    header: list = ["Species", "From", "To", "Required pts", "(enemy pts)"]
    rows: list = []
    for enemy_table in config["enemy"]:
        for (enemy, next_enemy) in pairwise(enemy_table["actors"]):
            if enemy["name"] == "Enemy_Moriblin_Senior_Volcano":
                continue
            rows.append([
                enemy_table["species"],
                object_names[enemy["name"]],
                object_names[next_enemy["name"]],
                enemy["value"] / multiplier,
                enemy["value"]
            ])

    rows.sort(key=lambda item: item[3])

    t = get_table_printer()
    t.header(header)
    t.set_cols_align(["l", "l", "l", "r", "r"])
    t.add_rows(rows, header=False)
    print(t.draw())

    write_csv(args.enemy_scaling_csv, header, rows)

def byml_modifier_to_string(modifier: int) -> str:
    return {
        -1: "",
        0: " ⭐",
        1: " ⭐⭐",
    }.get(modifier, "[Unknown modifier]")

def byml_weapon_entry_to_string(weapon) -> str:
    return object_names.get(weapon["name"], weapon["name"]) + \
        byml_modifier_to_string(weapon["plus"])

def print_weapon_scaling_list() -> None:
    print("\nWeapon scaling list")
    multiplier = config["setting"]["Level2WeaponPower"]
    print("Note: 1 point = %.3f weapon points" % multiplier)

    rows: list = []
    header: list = ["Series", "From", "To", "Required pts", "(weapon pts)"]

    def handle_weapon_list(weapon_list, weapon_table) -> None:
        for (weapon, next_weapon) in pairwise(weapon_list):
            rows.append([
                weapon_table["series"],
                byml_weapon_entry_to_string(weapon),
                byml_weapon_entry_to_string(next_weapon),
                weapon["value"] / multiplier,
                weapon["value"]
            ])

    for weapon_table in config["weapon"]:
        if weapon_table["not_rank_up"]:
            d: collections.defaultdict = collections.defaultdict(list)
            for weapon in weapon_table["actors"]:
                d[weapon["name"]].append(weapon)

            for weapon_list in d.values():
                handle_weapon_list(weapon_list, weapon_table)
        else:
            handle_weapon_list(weapon_table["actors"], weapon_table)

    rows.sort(key=lambda item: item[3])

    t = get_table_printer()
    t.header(header)
    t.set_cols_align(["l", "l", "l", "r", "r"])
    t.add_rows(rows, header=False)
    print(t.draw())

    write_csv(args.weapon_scaling_csv, header, rows)

print_kill_table()
print_enemy_scaling_list()
print_weapon_scaling_list()
