def sum_even(numbers):
    return sum(x for x in numbers if isinstance(x, int) and x % 2 == 0)
