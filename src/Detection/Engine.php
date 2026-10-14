<?php

declare(strict_types=1);

namespace AdelWAF\Detection;

use AdelWAF\Http\Request;

/** Anomaly-scoring engine: sums the scores of matching rules; caller compares to a threshold. */
final class Engine
{
    public const VERSION = '2.0.0';

    /**
     * @param list<array{path?:string,param?:string,rules?:list<string>}> $exclusions
     */
    public function __construct(
        private RuleSet $ruleSet,
        private int $paranoia = 1,
        private int $maxValueLen = 8192,
        private int $normalizeDepth = 3,
        private array $exclusions = [],
    ) {
    }

    /**
     * @return array{score:int,matches:list<array{id:string,category:string,score:int,target:string,name:string,sample:string}>}
     */
    public function inspect(Request $request): array
    {
        $matches = [];
        $score = 0;
        $path = $request->path();
        $byTarget = [];
        foreach ($this->ruleSet->rules() as $rule) {
            if ($rule->paranoia > $this->paranoia) {
                continue;
            }
            foreach ($rule->targets as $t) {
                $byTarget[$t][] = $rule;
            }
        }

        foreach ($request->inspectables($this->maxValueLen) as [$target, $name, $value]) {
            if ($value === '' || !isset($byTarget[$target])) {
                continue;
            }
            $normalized = null;
            foreach ($byTarget[$target] as $rule) {
                if ($rule->names !== [] && !in_array(strtolower($name), $rule->names, true)) {
                    continue;
                }
                if ($this->excluded($rule, $path, $name)) {
                    continue;
                }
                $subject = $value;
                if ($rule->normalize) {
                    $normalized ??= Normalizer::normalize($value, $this->normalizeDepth);
                    $subject = $normalized;
                }
                $hit = @preg_match($rule->pattern, $subject, $m);
                if ($hit !== 1 && $rule->normalize && $subject !== $value) {
                    $hit = @preg_match($rule->pattern, $value, $m);
                }
                if ($hit === 1) {
                    $score += $rule->score;
                    $matches[] = [
                        'id' => $rule->id,
                        'category' => $rule->category,
                        'score' => $rule->score,
                        'target' => $target,
                        'name' => substr($name, 0, 80),
                        'sample' => substr(preg_replace('/[^\x20-\x7E]/', '?', $m[0] ?? '') ?? '', 0, 80),
                    ];
                }
            }
        }

        return ['score' => $score, 'matches' => $matches];
    }

    private function excluded(Rule $rule, string $path, string $name): bool
    {
        foreach ($this->exclusions as $ex) {
            if (isset($ex['path']) && !fnmatch($ex['path'], $path)) {
                continue;
            }
            if (isset($ex['param'])) {
                $bare = str_starts_with($name, '(key)') ? substr($name, 5) : $name;
                if (!fnmatch($ex['param'], $bare)) {
                    continue;
                }
            }
            $ids = $ex['rules'] ?? ['*'];
            if (in_array('*', $ids, true) || in_array($rule->id, $ids, true) || in_array($rule->category, $ids, true)) {
                return true;
            }
        }

        return false;
    }
}
