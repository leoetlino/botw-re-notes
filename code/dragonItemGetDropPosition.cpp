struct Vec3 {
  float x, y, z;
};

bool getDragonItemDropPosition(Vec3* targetPos, const Vec3* pos) {  // 0x710000AF44
  const auto* traverseResult =
      PlacementMgr::sInstance->traverseResults[1 - PlacementMgr::sInstance->traverseResultIdxMaybe];

  // Choose 3 drop targets that are closest to the dragon
  // Only targets that are *below* the dragon (the item) are considered
  const auto possibleTargets =
      util::makeRange(traverseResult->dragonItemDropTargets) |
      util::filter([&](const auto& obj) { return obj.translate.y < pos->y; }) |
      util::getBiggest<3>([&](const auto& obj) { return pos->distance2(obj.translate); });

  // If there are no valid targets, the drop will be sent to (0, 0, 0)...
  if (possibleTargets.empty())
    return false;

  // Pick one of the targets randomly.
  const int indexToUse = sead::GlobalRandom::sInstance->getU32() % 3;
  *targetPos = possibleTargets[indexToUse];
  // If the distance to the target is >= 1000.0, the drop will still move to (0, 0, 0)...
  return true;
}
